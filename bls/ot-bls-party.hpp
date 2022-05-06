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

    int INPUTSIZE = 4;
    int COMMON = 2;
    int TOTAL_GENERATED_INPUTS = INPUTSIZE*2 - COMMON;
    int secondPlayerInputIdx = INPUTSIZE - COMMON;
    OnlineOptions::singleton.batch_size = INPUTSIZE * INPUTSIZE * 10;

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
    uint8_t message[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}; // claim of p1
    uint8_t message2[10] = { 10, 12, 7, 3, 4, 5, 16, 7, 8, 9}; // claim of p2

    SeededPRNG G;
    if (P.my_num() == 0){
        // Generate secret keys and signatures with them
        cout << "generating random keys and signatures" << endl;
        G1Element::Scalar sk;

        
        for (int i = 0; i < TOTAL_GENERATED_INPUTS; i++)
        {
            // chose random sk
            sk.randomize(G);
            // create pk
            G2Element Pk(sk);

            // sign1
            G1Element signature = G1Element::sign(message, sizeof(message), sk);
            assert(G1Element::ver(signature, message, sizeof(message), Pk) == true);
            generatedinputsA.push_back({Pk, signature});

            // sign2            
            G1Element signature2 = G1Element::sign(message2, sizeof(message2), sk);
            assert(G1Element::ver(signature2, message2, sizeof(message2), Pk) == true);
            generatedinputsB.push_back({Pk, signature2});
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


    if (P.my_num() == 0){
        for (int i = 0; i < INPUTSIZE; i++){
            E_set.push_back(pair_g1_g2(msg_to_g1(message, sizeof(message)), pciinputs[i].Pk));
            E_set_.push_back(pair_g1_g2(msg_to_g1(message2, sizeof(message2)), pciinputs[i].Pk));
        }
    } else if (P.my_num() == 1){
        for (int i = 0; i < INPUTSIZE; i++){
            E_set.push_back(pair_g1_g2(msg_to_g1(message2, sizeof(message2)), pciinputs[i].Pk));
            E_set_.push_back(pair_g1_g2(msg_to_g1(message, sizeof(message)), pciinputs[i].Pk));
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
    cout << "Input sharing took " << tinput * 1e3 << " ms" << endl;




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

    cout << "---- main loop ----" << N.my_num() << endl;
    for (int i = 0; i < INPUTSIZE; i++)
    {
        for (int j = 0; j < INPUTSIZE; j++){
            c3.push_back((E_share[0][i] - E_share_[1][j]) + (E_share[1][j] - E_share_[0][i]));
        }
    }
    for (int i = 0; i < INPUTSIZE; i++)
    {
        for (int j = 0; j < INPUTSIZE; j++){
            c4.push_back(c3[(INPUTSIZE*i) + j] + c1[i] + c2[j]);
        }
    }



    // Test
    typename gtShare::clear gt_result;
    typename g2Share::clear g2_result;
    GtElement gtunity;
    gt_output.init_open(P);
    for (int i = 0; i < INPUTSIZE; i++)
    {
        for (int j = 0; j < INPUTSIZE; j++){
            gt_output.prepare_open(c3[(INPUTSIZE*i) + j]);
        }
    }
    gt_output.exchange(P);

    g2_output.init_open(P);
    int outputlen = 0;

    for (int i = 0; i < INPUTSIZE; i++)
    {
        for (int j = 0; j < INPUTSIZE; j++){
            gt_result = gt_output.finalize_open();
            cout << gt_result << endl;
            if(gt_result == gtunity){
                cout << "match" << endl;
                g2_output.prepare_open(Pk_share[0][i]);
                outputlen++;
            }
        }
    }
    gt_output.Check(P);

    cout << "------------- output ---------------" <<endl;
    g2_output.exchange(P);
    for (int i = 0; i < outputlen; i++)
    {
        g2_result = g2_output.finalize_open();
        cout << g2_result << endl;
    }
    g2_output.Check(P);
    

    


    // cout << "Testing relic " << endl;

    // if (core_init() != RLC_OK) {
	// 	core_clean();
	// 	return;
	// }
    // pc_param_set_any();

    // cout << "-----------" << endl;
    // bn_t g1_order, g2_order, gt_order;
    // bn_null(g1_order);
    // bn_null(g2_order);
    // bn_null(gt_order);
    // g1_get_ord(g1_order);
    // g2_get_ord(g2_order);
    // gt_get_ord(gt_order);
    // bn_print(g1_order);
    // bn_print(g2_order);
    // bn_print(gt_order);
    // cout << "-----------" << endl;


	// bn_t sk1, sk2;
    // g1_t sig1, sig2, sig;
	// g2_t pk1, pk2, pk;
	// uint8_t m[5] = { 0, 1, 2, 3, 4 };

	// bn_null(sk1);
	// bn_null(sk2);
    // bn_new(sk1);
    // bn_new(sk2);
    // g1_new(sig1);
    // g1_new(sig2);

    // g2_null(pk1);
    // g2_null(pk2);
    // g2_null(pk);

    // g2_new(pk1);
    // g2_new(pk2);
    // g2_new(pk);

    // assert(cp_bls_gen(sk1, pk1) == RLC_OK);
    // assert(cp_bls_gen(sk2, pk2) == RLC_OK);
    // cout << "gen" << endl;
    // assert(cp_bls_sig(sig1, m, sizeof(m), sk1) == RLC_OK);
    // assert(cp_bls_sig(sig2, m, sizeof(m), sk2) == RLC_OK);
    // cout << "sig" << endl;
    // assert(cp_bls_ver(sig1, m, sizeof(m), pk1) == 1);
    // assert(cp_bls_ver(sig2, m, sizeof(m), pk2) == 1);
    // cout << "ver" << endl;

    // g1_add(sig, sig1, sig2);
    // g2_add(pk, pk1, pk2);
    // assert(cp_bls_ver(sig, m, sizeof(m), pk) == 1);

    // gt_t pres1, pres2;
    // gt_null(pres1);
    // gt_null(pres2);
    // gt_new(pres1);
    // gt_new(pres2);
    // g2_t g2gen;
    // g2_null(g2gen);
    // g2_new(g2gen);
    // g2_get_gen(g2gen);
    // g1_t mg1;
    // g1_null(mg1);
    // g1_new(mg1);
    // g1_map(mg1, m, sizeof(m));
    // pc_map(pres1, sig, g2gen);
    // pc_map(pres2, mg1, pk);
    // gt_print(pres1);
    // gt_print(pres2);
    // gt_inv(pres2, pres2);
    // gt_mul(pres1, pres1, pres2);
    // gt_print(pres1);
    // cout << "ver aggregate" << endl;
    // return;



//     // scalar processing units ====================
//     DataPositions usage(P.num_players());

//     typedef T<GtElement::Scalar> scalarShare;

//     typename scalarShare::mac_key_type mac_key;
//     scalarShare::read_or_generate_mac_key("", P, mac_key);

//     typename scalarShare::Direct_MC output(mac_key);

//     typename scalarShare::LivePrep preprocessing(0, usage);
    
//     SubProcessor<scalarShare> processor(output, preprocessing, P);

//     typename scalarShare::Input input(output, preprocessing, P);
//     // =============================================

//     P256Element::Scalar sk;
//     sk.randomize(G);
//     GtElement gtval(sk);
//     G1Element g1val(sk);
//     G2Element g2val(sk);
//     sk.randomize(G);
//     GtElement gtval3(sk);
//     G2Element g2val2(sk);

//     gtval.print_point();
//     GtElement gtval2 = gtval;
//     cout << "----" << endl;
//     gtval2.print_point();

//     cout <<(gtval2 == gtval) << endl;
//     cout <<(gtval2 == gtval3) << endl;

//     cout << gtval << endl;
//     cout << gtval2 << endl;
//     cout << gtval3 << endl;

//     typedef T<GtElement::Scalar> scalarShare;
//     scalarShare a;
//     cout << a << endl;

//     typedef T<GtElement> gtShare;
//     gtShare p,q;
//     cout << p << endl;


//     // gt processing units ====================

//     MascotEcPrep<gtShare, scalarShare> gt_preprocessing(usage, preprocessing);
    
//     typename gtShare::mac_key_type gt_mac_key;
//     gtShare::read_or_generate_mac_key("", P, gt_mac_key);


//     typename gtShare::Direct_MC gt_output(output.get_alphai());
    

//     typename gtShare::Input gt_input(gt_output, gt_preprocessing, P);
// // 
//     // EcBeaver<gtShare, scalarShare> ecprotocol(P);
//     // ecprotocol.init(preprocessing, gt_output, output);
//     // ============================================
 
//     vector<gtShare> gt_inputs_shares[2];
//     gt_input.reset_all(P);
//     gt_input.add_from_all(gtval);
//     gt_input.exchange();
//     gt_inputs_shares[0].push_back(gt_input.finalize(0));
//     gt_inputs_shares[1].push_back(gt_input.finalize(1));

//     typename gtShare::clear gt_result;
//     gt_output.init_open(P);
//     gt_output.prepare_open(gt_inputs_shares[0][0]);
//     gt_output.exchange(P);
//     gt_result = gt_output.finalize_open();
//     cout << "-->" << gtval << endl;
//     cout << "-->" << gt_result << endl;
//     gt_output.Check(P);


//     // g1 processing units ====================
//     typedef T<G1Element> g1Share;

//     MascotEcPrep<g1Share, scalarShare> g1_preprocessing(usage, preprocessing);
    
//     typename g1Share::mac_key_type g1_mac_key;
//     g1Share::read_or_generate_mac_key("", P, g1_mac_key);


//     typename g1Share::Direct_MC g1_output(output.get_alphai());
    

//     typename g1Share::Input g1_input(g1_output, g1_preprocessing, P);


//     vector<g1Share> g1_inputs_shares[2];
//     g1_input.reset_all(P);
//     g1_input.add_from_all(g1val);
//     g1_input.exchange();
//     g1_inputs_shares[0].push_back(g1_input.finalize(0));
//     g1_inputs_shares[1].push_back(g1_input.finalize(1));

//     typename g1Share::clear g1_result;
//     g1_output.init_open(P);
//     g1_output.prepare_open(g1_inputs_shares[0][0]);
//     g1_output.exchange(P);
//     g1_result = g1_output.finalize_open();
//     cout << "-->" << g1val << endl;
//     cout << "-->" << g1_result << endl;
//     g1_output.Check(P);






//     // g2 processing units ====================
//     typedef T<G2Element> g2Share;

//     MascotEcPrep<g2Share, scalarShare> g2_preprocessing(usage, preprocessing);
    
//     typename g2Share::mac_key_type g2_mac_key;
//     g2Share::read_or_generate_mac_key("", P, g2_mac_key);


//     typename g2Share::Direct_MC g2_output(output.get_alphai());
    

//     typename g2Share::Input g2_input(g2_output, g2_preprocessing, P);


//     vector<g2Share> g2_inputs_shares[2];
//     g2_input.reset_all(P);
//     g2_input.add_from_all(g2val);
//     g2_input.add_from_all(g2val2);
//     g2_input.exchange();
//     g2_inputs_shares[0].push_back(g2_input.finalize(0));
//     g2_inputs_shares[1].push_back(g2_input.finalize(1));
//     g2_inputs_shares[0].push_back(g2_input.finalize(0));
//     g2_inputs_shares[1].push_back(g2_input.finalize(1));

//     typename g2Share::clear g2_result;
//     g2_output.init_open(P);
//     g2_output.prepare_open(g2_inputs_shares[0][0]);
//     g2_output.prepare_open(g2_inputs_shares[0][1]);
//     g2_output.exchange(P);
//     g2_result = g2_output.finalize_open();
//     cout << "-->" << g2val << endl;
//     cout << "-->" << g2_result << endl;
//     g2_result = g2_output.finalize_open();
//     cout << "-->" << g2val2 << endl;
//     cout << "-->" << g2_result << endl;

//     g2_output.Check(P);

//     cout << "----------------------------" << endl;


//     cout << "----------  TEST PAIR G1-P ------------------" << endl;
//     g2_t g2gen;
//     g2_null(g2gen);
//     g2_new(g2gen);
//     g2_get_gen(g2gen);

//     g1_t g1x;
//     g1_null(g1x);
//     g1_new(g1x);
//     g1val.copypoint(g1x);

//     gt_t gtres;
//     gt_null(gtres);
//     gt_new(gtres);
//     gt_get_gen(gtres);

//     pc_map(gtres, g1x, g2gen);


//     gt_print(gtres);
//     cout << "................."<< endl;

//     cout << GtElement(gtres, false) << endl;


//     g2_free(g2gen);
//     gt_free(gtres);
//     g1_free(g1x);
    
//     g1Share aa = g1_inputs_shares[0][0];
//     gtShare bb;
//     pair_g1_p(aa, bb);

//     gt_output.init_open(P);
//     gt_output.prepare_open(bb);
//     gt_output.exchange(P);
//     gt_result = gt_output.finalize_open();
//     cout << "-->" << gt_result << endl;
//     gt_output.Check(P);
    
    
//     EcBeaver<gtShare, scalarShare> ecprotocol(P);
    // ecprotocol.init(preprocessing, gt_output, output);


    
}
