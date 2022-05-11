/*
 * fake-spdz-bls-party.cpp
 *
 */

#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Math/gfp.h"
#include "bls/P256Element.h"


#include "Protocols/SemiShare.h"
#include "Processor/BaseMachine.h"

#include "bls/preprocessing.hpp"
#include "bls/sign.hpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/EcBeaver.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/MascotPrep.hpp"
#include "Protocols/MascotEcPrep.hpp"
#include "Processor/Processor.hpp"
#include "Processor/Data_Files.hpp"
#include "Processor/Input.hpp"
#include "GC/TinyPrep.hpp"
#include "GC/VectorProtocol.hpp"
#include "GC/CcdPrep.hpp"

#include <assert.h>
#include "bls/blsElement.h"

#include "thread_pool.hpp"


extern "C" {
#include <relic/relic_core.h>
#include <relic/relic_bn.h>
#include <relic/relic_pc.h>
#include <relic/relic_cp.h>
}

class PCIBLSInput
{
public:
    G2Element Pk;
    G1Element signature;

    void pack(octetStream& os) const
    {
        Pk.pack(os);
        signature.pack(os);
    }

    void unpack(octetStream& os)
    {
        Pk.unpack(os);
        signature.unpack(os);
    }

};

// Function for Scalar multiplication of A p256 share and a clear gfp
void ecscalarmulshare(Share<P256Element> pointshare, P256Element::Scalar multiplier, Share<P256Element>& result){
    result.set_share(pointshare.get_share() * multiplier);
    result.set_mac(pointshare.get_mac() * multiplier);
}

// Function for Scalar multiplication of a clear p256 and a shared gfp
void ecscalarmulshare(P256Element point, Share<P256Element::Scalar> multiplierShare, Share<P256Element>& result){
    result.set_share(point * multiplierShare.get_share());
    result.set_mac(point * multiplierShare.get_mac());
}

Share<GtElement> pair_g1share_p(Share<G1Element> g1shareip){
    Share<GtElement> result;

    gt_t res;
    gt_null(res);
    gt_new(res);

    g2_t g2gen;
    g2_null(g2gen);
    g2_new(g2gen);

    g1_t g1val, g1mac;
    g1_null(g1val);
    g1_null(g1mac);
    g1_new(g1val);
    g1_new(g1mac);
    G1Element val = g1shareip.get_share();
    G1Element mac = g1shareip.get_mac();
    val.copypoint(g1val);
    mac.copypoint(g1mac);
    
    g2_get_gen(g2gen);

    pc_map(res, g1val, g2gen);
    GtElement v(res, false);
    result.set_share(v);

    pc_map(res, g1mac, g2gen);
    GtElement m(res, false);
    result.set_mac(m);
    gt_free(res);
    g2_free(g2gen);
    g1_free(g1val);
    g1_free(g1mac);
    return result;
}


Share<GtElement> exp_gt_scalar(Share<GtElement> gtshareip, GtElement::Scalar multiplier){
    Share<GtElement> result;

    GtElement val = gtshareip.get_share();
    GtElement mac = gtshareip.get_mac();

    result.set_share(val * multiplier);
    result.set_mac(mac * multiplier);

    return result;
}




template<template<class U> class T>
void run(int argc, const char** argv)
{
    ez::ezOptionParser opt;
    BlsOptions opts(opt, argc, argv);
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Use SimpleOT instead of OT extension", // Help description.
            "-S", // Flag token.
            "--simple-ot" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Don't check correlation in OT extension (only relevant with MASCOT)", // Help description.
            "-U", // Flag token.
            "--unchecked-correlation" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Fewer rounds for authentication (only relevant with MASCOT)", // Help description.
            "-A", // Flag token.
            "--auth-fewer-rounds" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Use Fiat-Shamir for amplification (only relevant with MASCOT)", // Help description.
            "-H", // Flag token.
            "--fiat-shamir" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Skip sacrifice (only relevant with MASCOT)", // Help description.
            "-E", // Flag token.
            "--embrace-life" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "No MACs (only relevant with MASCOT; implies skipping MAC checks)", // Help description.
            "-M", // Flag token.
            "--no-macs" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Input Size", // Help description.
            "-I", // Flag token.
            "--inputs" // Flag token.
    );
    opt.parse(argc, argv);
    int INPUTSIZE = 10;
    if (opt.get("-I")->isSet){
        opt.get("-I")->getInt(INPUTSIZE);
    }
    else {
        cout << "default input size 10" << endl;
    }
    cout << ">>>> Input size (each party)," << INPUTSIZE << "," << endl;
    
    thread_pool pool;

    int COMMON = 1;
    int TOTAL_GENERATED_INPUTS = INPUTSIZE*2 - COMMON;
    int secondPlayerInputIdx = INPUTSIZE - COMMON;
    OnlineOptions::singleton.batch_size = INPUTSIZE * 10;

    // Setup network with two players
    Names N(opt, argc, argv, 2);

    // Setup PlainPlayer
    PlainPlayer P(N, "bls");
   
    BaseMachine machine;
    machine.ot_setups.push_back({P, true});


    // Initialize curve and field
    // Initializes the field order to same as curve order 
    GtElement::init_relic();
    GtElement::init();

    // Initialize scalar:next with same order as field order. ??
    GtElement::Scalar::next::init_field(GtElement::Scalar::pr(), false);

    cout << "chosen order: " << endl;
    cout << GtElement::Scalar::pr() << endl;

    // Input generation , let P0 perform it ================================
    vector<PCIBLSInput> pciinputs;
    vector<PCIBLSInput> generatedinputsA;
    vector<PCIBLSInput> generatedinputsB;
    ClearInput<PCIBLSInput> clearInput(P);
    uint8_t message11[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}; // claim of p1
    uint8_t message12[10] = { 0, 1, 2, 23, 4, 5, 6, 7, 18, 19}; // claim of p1
    uint8_t message21[10] = { 10, 12, 7, 3, 4, 5, 16, 7, 8, 9}; // claim of p2
    uint8_t message22[10] = { 10, 12, 7, 43, 4, 55, 16, 17, 8, 9}; // claim of p2

    SeededPRNG G;
    if (P.my_num() == 0){
        // Generate secret keys and signatures with them
        cout << "generating random keys and signatures" << endl;
        G1Element::Scalar sk;

        G1Element signature1, signature2;
        for (int i = 0; i < TOTAL_GENERATED_INPUTS; i++)
        {
            // chose random sk
            sk.randomize(G);
            // create pk
            G2Element Pk(sk);

            // sign1
            signature1 = G1Element::sign(message11, sizeof(message11), sk);
            assert(G1Element::ver(signature1, message11, sizeof(message11), Pk) == true);
            signature2 = G1Element::sign(message12, sizeof(message12), sk);
            assert(G1Element::ver(signature2, message12, sizeof(message12), Pk) == true);
            signature1 = signature1 + signature2;
            generatedinputsA.push_back({Pk, signature1});

            // sign2
            signature1 = G1Element::sign(message21, sizeof(message21), sk);
            assert(G1Element::ver(signature1, message21, sizeof(message21), Pk) == true);
            signature2 = G1Element::sign(message22, sizeof(message22), sk);
            assert(G1Element::ver(signature2, message22, sizeof(message22), Pk) == true);
            signature1 = signature1 + signature2;
            generatedinputsB.push_back({Pk, signature1});

        }


        cout << "distributing input keys and signatures" << endl;
        
        for (int i = 0; i < INPUTSIZE; i++){
            pciinputs.push_back(generatedinputsA[i]);
            cout << pciinputs[i].Pk << pciinputs[i].signature << endl;
        }


        clearInput.reset_all();
        for (int i = secondPlayerInputIdx; i < TOTAL_GENERATED_INPUTS; i++){
            clearInput.add_mine(generatedinputsB[i]);
        }
        clearInput.exchange();
    }

    if (P.my_num() == 1){
        clearInput.reset_all();
        for (int i = 0; i < INPUTSIZE; i++)
        {
            clearInput.add_other(0);
        }
        clearInput.exchange();
        for (int i = 0; i < INPUTSIZE; i++)
        {
            pciinputs.push_back(clearInput.finalize(0));
            cout << pciinputs[i].Pk << pciinputs[i].signature << endl;
        }
    }
    
    // Parties compute E and E' sets
    vector<GtElement> E_set;
    vector<GtElement> E_set_;
    G1Element m1combined = msg_to_g1(message11, sizeof(message11)) + msg_to_g1(message12, sizeof(message12));
    G1Element m2combined = msg_to_g1(message21, sizeof(message21)) + msg_to_g1(message22, sizeof(message22));

    if (P.my_num() == 0){
        for (int i = 0; i < INPUTSIZE; i++){
            E_set.push_back(
                pair_g1_g2(
                    m1combined,
                    pciinputs[i].Pk
                    ));
            E_set_.push_back(
                pair_g1_g2(
                    m2combined,
                    pciinputs[i].Pk
                    ));
        }
    } else if (P.my_num() == 1){
        for (int i = 0; i < INPUTSIZE; i++){
            E_set.push_back(
                pair_g1_g2(
                    m2combined,
                    pciinputs[i].Pk
                    ));
            E_set_.push_back(
                pair_g1_g2(
                    m1combined,
                    pciinputs[i].Pk
                    ));
        }
    }


    cout << "==========  Input generation done ============" << endl;
    Timer timer;
    timer.start();
    auto stats = P.total_comm();





    // scalar processing units ====================
    DataPositions usage(P.num_players());

    typedef T<GtElement::Scalar> scalarShare;

    typename scalarShare::mac_key_type mac_key;
    scalarShare::read_or_generate_mac_key("", P, mac_key);

    typename scalarShare::Direct_MC output(mac_key);

    typename scalarShare::LivePrep preprocessing(0, usage);
    
    SubProcessor<scalarShare> processor(output, preprocessing, P);

    typename scalarShare::Input input(output, preprocessing, P);
    // =============================================

    // g1 processing units ====================
    typedef T<G1Element> g1Share;

    MascotEcPrep<g1Share, scalarShare> g1_preprocessing(usage, preprocessing);
    
    typename g1Share::mac_key_type g1_mac_key;
    g1Share::read_or_generate_mac_key("", P, g1_mac_key);

    typename g1Share::Direct_MC g1_output(output.get_alphai());
    
    typename g1Share::Input g1_input(g1_output, g1_preprocessing, P);

    // =============================================


    // g2 processing units ====================
    typedef T<G2Element> g2Share;

    MascotEcPrep<g2Share, scalarShare> g2_preprocessing(usage, preprocessing);
    
    typename g2Share::mac_key_type g2_mac_key;
    g2Share::read_or_generate_mac_key("", P, g2_mac_key);


    typename g2Share::Direct_MC g2_output(output.get_alphai());
    

    typename g2Share::Input g2_input(g2_output, g2_preprocessing, P);

    // =============================================

    // gt processing units ====================
    typedef T<GtElement> gtShare;

    MascotEcPrep<gtShare, scalarShare> gt_preprocessing(usage, preprocessing);
    
    typename gtShare::mac_key_type gt_mac_key;
    gtShare::read_or_generate_mac_key("", P, gt_mac_key);


    typename gtShare::Direct_MC gt_output(output.get_alphai());
    

    typename gtShare::Input gt_input(gt_output, gt_preprocessing, P);

    EcBeaver<gtShare, scalarShare> gtprotocol(P);
    gtprotocol.init(preprocessing, gt_output, output);
    // =============================================


    cout <<  "------ Input S_i , Pk_i , Ei, E'i ----------" << endl;

    // Input Shares
    vector<g1Share> S_share[2];
    vector<g2Share> Pk_share[2];
    vector<gtShare> E_share[2];
    vector<gtShare> E_share_[2];


    // Give Input
    g1_input.reset_all(P);
    g2_input.reset_all(P);
    gt_input.reset_all(P);
    for (int i = 0; i < INPUTSIZE; i++){
        g1_input.add_from_all(pciinputs[i].signature);
        g2_input.add_from_all(pciinputs[i].Pk);
        gt_input.add_from_all(E_set[i]);
        gt_input.add_from_all(E_set_[i]);
    }
    g1_input.exchange();
    g2_input.exchange();
    gt_input.exchange();
    for (int i = 0; i < INPUTSIZE; i++)
    {
        // shares of party A
        S_share[0].push_back(g1_input.finalize(0));
        Pk_share[0].push_back(g2_input.finalize(0));
        E_share[0].push_back(gt_input.finalize(0));
        E_share_[0].push_back(gt_input.finalize(0));

        // shares of party B
        S_share[1].push_back(g1_input.finalize(1));
        Pk_share[1].push_back(g2_input.finalize(1));
        E_share[1].push_back(gt_input.finalize(1));
        E_share_[1].push_back(gt_input.finalize(1));

    }
    cout << "---- inputs shared ----" << N.my_num() << endl;

    auto tinput = timer.elapsed();
    cout << ">>>> Input sharing," << tinput * 1e3 << ", ms" << endl;




    cout << "---- computing c1i and c2j ----" << N.my_num() << endl;

    vector<gtShare> c1;
    vector<gtShare> c2;
    for (int i = 0; i < INPUTSIZE; i++)
    {
        gtShare tmp;
        tmp = pair_g1share_p(S_share[0][i]);
        tmp = tmp - E_share[0][i];
        c1.push_back(tmp);

        tmp = pair_g1share_p(S_share[1][i]);
        tmp = tmp - E_share[1][i];
        c2.push_back(tmp);
    }

    vector<gtShare> c3;
    vector<gtShare> c4;
    vector<gtShare> c4_rand;

    auto tc1c2 = timer.elapsed();
    cout << ">>>> C1 C2 computation," << (tc1c2 - tinput) * 1e3 << ", ms" << endl;


    cout << "---- main loop ----" << N.my_num() << endl;

    cout << "------  generate randoms ------" << endl;
    vector<scalarShare> to_open_rands;
    vector<GtElement::Scalar> open_rands;
    vector<scalarShare> myrandomshares;
    scalarShare __;

    for (int i = 0; i < 3; i++){
            to_open_rands.push_back({});
            preprocessing.get_two(DATA_INVERSE, to_open_rands.back(), __);
    }
    // open the shares
    cout << "------  opening 3 randoms ------" << endl;
    output.init_open(P);
    for (int i = 0; i < 3; i++){
        output.prepare_open(to_open_rands[i]);
    }
    output.exchange(P);
    for (int i = 0; i < 3; i++){
        open_rands.push_back(output.finalize_open());
    }
    output.Check(P);

    auto topen3rand = timer.elapsed();
    cout << ">>>> Open 3 rands," << (topen3rand - tc1c2) * 1e3 << ", ms" << endl;


    cout << "------  generate " << (INPUTSIZE * INPUTSIZE) << " randoms ------" << endl;

    for (int i = 0; i < INPUTSIZE; i++){
        for (int j = 0; j < INPUTSIZE; j++){
            typename scalarShare::clear tmp;
            myrandomshares.push_back({});
            preprocessing.get_two(DATA_INVERSE, myrandomshares.back(), __);
            // cout << "generating rand " << (INPUTSIZE*i + j) << endl;
            // ecprotocol.prepare_scalar_mul(myrandomshares.back(), c_final[INPUTSIZE*i + j]);;
        }
    }
    cout << "-- done --" << endl;

    auto tprand = timer.elapsed();
    cout << ">>>> Generate INPUT**2 private rands," << (tprand - topen3rand) * 1e3 << ", ms" << endl;

    cout << "-- computing c3 --" << endl;
    c3.resize(INPUTSIZE*INPUTSIZE);
    for (int i = 0; i < INPUTSIZE; i++)
    {
        for (int j = 0; j < INPUTSIZE; j++){
            gtShare e01 = E_share[0][i];
            gtShare e_1j = E_share_[1][j];
            gtShare e1j = E_share[1][j];
            gtShare e_01 = E_share_[0][i];
            GtElement::Scalar or0 = open_rands[0];

            pool.push_task([&c3, e01, e_1j, e1j, e_01, or0, i,j, INPUTSIZE]{
                c3[i*INPUTSIZE + j] = (e01 - e_1j) + exp_gt_scalar((e1j - e_01), or0);
                });
                // c3[i*INPUTSIZE + j] = (E_share[0][i] - E_share_[1][j]) + exp_gt_scalar((E_share[1][j] - E_share_[0][i]), open_rands[0]);

        }
    }
    pool.wait_for_tasks();

    auto tc3 = timer.elapsed();
    cout << ">>>> C3 computation," << (tc3 - tprand) * 1e3 << ", ms" << endl;

    cout << "-- computing c4 --" << endl;
    c4.resize(INPUTSIZE*INPUTSIZE);
    for (int i = 0; i < INPUTSIZE; i++)
    {
        for (int j = 0; j < INPUTSIZE; j++){
            gtShare c3item = c3[(INPUTSIZE*i) + j];
            gtShare c1item = c1[i];
            gtShare c2item = c2[j];
            GtElement::Scalar or1 = open_rands[1];
            GtElement::Scalar or2 = open_rands[2];
            pool.push_task([&c4, c1item, c2item, c3item, or1, or2, open_rands, i,j, INPUTSIZE]{
                c4[(INPUTSIZE*i) + j] = c3item + exp_gt_scalar(c1item, or1) + exp_gt_scalar(c2item, or2);
                });
                // c4[(INPUTSIZE*i) + j] = c3[(INPUTSIZE*i) + j] + exp_gt_scalar(c1[i], open_rands[1]) + exp_gt_scalar(c2[j], open_rands[2]);

        }
    }
    pool.wait_for_tasks();


    auto tc4 = timer.elapsed();
    cout << ">>>> C4 computation," << (tc4 - tc3) * 1e3 << ", ms" << endl;


    cout << "-- private random * c4s --" << endl;
    gtprotocol.init_mul();
    for (int i = 0; i < INPUTSIZE; i++)
    {
        for (int j = 0; j < INPUTSIZE; j++){
            gtprotocol.prepare_scalar_mul(myrandomshares[(INPUTSIZE*i) + j], c4[(INPUTSIZE*i) + j]);
        }
    }
    gtprotocol.exchange();
    gtprotocol.finalize_mul(INPUTSIZE*INPUTSIZE, pool, c4_rand);

    auto tc4_rand = timer.elapsed();
    cout << ">>>> C4 * private rand computation," << (tc4_rand - tc4) * 1e3 << ", ms" << endl;


    // Test
    cout << "-- opening c4_rand --" << endl;
    typename gtShare::clear gt_result;
    typename g2Share::clear g2_result;
    GtElement gtunity;
    gt_output.init_open(P);
    for (int i = 0; i < INPUTSIZE; i++)
    {
        for (int j = 0; j < INPUTSIZE; j++){
            gt_output.prepare_open(c4_rand[(INPUTSIZE*i) + j]);
        }
    }
    gt_output.exchange(P);
    cout << "-- exchanging c4_rand complete --" << endl;

    g2_output.init_open(P);
    int outputlen = 0;

    for (int i = 0; i < INPUTSIZE; i++)
    {
        for (int j = 0; j < INPUTSIZE; j++){
            gt_result = gt_output.finalize_open();
            // cout << gt_result << endl;
            if(gt_result == gtunity){
                // cout << "match" << endl;
                g2_output.prepare_open(Pk_share[0][i]);
                outputlen++;
            }
        }
    }
    auto tc4_open = timer.elapsed();
    cout << ">>>> Open C4," << (tc4_open - tc4_rand) * 1e3 << ", ms" << endl;

    cout << "-- maccheck 1 --" << endl;

    gt_output.Check(P);

    auto tmc1 = timer.elapsed();
    cout << ">>>> Mac check 1," << (tmc1 - tc4_open) * 1e3 << ", ms" << endl;


    cout << "------------- output ---------------" <<endl;
    g2_output.exchange(P);
    for (int i = 0; i < outputlen; i++)
    {
        g2_result = g2_output.finalize_open();
        cout << g2_result << endl;
    }
    auto tres = timer.elapsed();
    cout << ">>>> Open output," << (tres - tmc1) * 1e3 << ", ms" << endl;

    cout << "-- maccheck 2 --" << endl;

    g2_output.Check(P);
    auto tmc2 = timer.elapsed();
    cout << ">>>> Mac check 2," << (tmc2 - tres) * 1e3 << ", ms" << endl;

    cout << "-- end --" << endl;

    cout << ">>>> Final time," << timer.elapsed() * 1e3 << ", ms" << endl;
    (P.total_comm() - stats).print(true);


    
}
