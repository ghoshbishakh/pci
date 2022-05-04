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

// extern "C" {
// #include <relic/relic_core.h>
// #include <relic/relic_bn.h>
// #include <relic/relic_pc.h>
// #include <relic/relic_cp.h>
// }

class PCIInput
{
public:
    P256Element Pk;
    EcSignature signature;

    void pack(octetStream& os) const
    {
        Pk.pack(os);
        signature.R.pack(os);
        signature.s.pack(os);
    }

    void unpack(octetStream& os)
    {
        Pk.unpack(os);
        signature.R.unpack(os);
        signature.s.unpack(os);
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



    // Setup network with two players
    Names N(opt, argc, argv, 2);

    // Setup PlainPlayer
    PlainPlayer P(N, "bls");
   
    BaseMachine machine;
    machine.ot_setups.push_back({P, true});




    cout << "Testing relic " << endl;

    // Initialize curve and field
    // Initializes the field order to same as curve order 
    GtElement::init_relic();
    GtElement::init();

    // Initialize scalar:next with same order as field order. ??
    GtElement::Scalar::next::init_field(GtElement::Scalar::pr(), false);
    
    cout << GtElement::Scalar::pr() << endl;
    cout << GtElement::Scalar::next::pr() << endl;

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

    SeededPRNG G;
    P256Element::Scalar sk;
    sk.randomize(G);
    GtElement gtval(sk);
    G1Element g1val(sk);
    sk.randomize(G);
    GtElement gtval3(sk);

    gtval.print_point();
    GtElement gtval2 = gtval;
    cout << "----" << endl;
    gtval2.print_point();

    cout <<(gtval2 == gtval) << endl;
    cout <<(gtval2 == gtval3) << endl;

    cout << gtval << endl;
    cout << gtval2 << endl;
    cout << gtval3 << endl;

    typedef T<GtElement::Scalar> scalarShare;
    scalarShare a;
    cout << a << endl;

    typedef T<GtElement> gtShare;
    gtShare p,q;
    cout << p << endl;


    // gt processing units ====================

    MascotEcPrep<gtShare, scalarShare> gt_preprocessing(usage, preprocessing);
    
    typename gtShare::mac_key_type gt_mac_key;
    gtShare::read_or_generate_mac_key("", P, gt_mac_key);


    typename gtShare::Direct_MC gt_output(output.get_alphai());
    

    typename gtShare::Input gt_input(gt_output, gt_preprocessing, P);
// 
    // EcBeaver<gtShare, scalarShare> ecprotocol(P);
    // ecprotocol.init(preprocessing, gt_output, output);
    // ============================================
 
    vector<gtShare> gt_inputs_shares[2];
    gt_input.reset_all(P);
    gt_input.add_from_all(gtval);
    gt_input.exchange();
    gt_inputs_shares[0].push_back(gt_input.finalize(0));
    gt_inputs_shares[1].push_back(gt_input.finalize(1));

    typename gtShare::clear gt_result;
    gt_output.init_open(P);
    gt_output.prepare_open(gt_inputs_shares[0][0]);
    gt_output.exchange(P);
    gt_result = gt_output.finalize_open();
    cout << "-->" << gtval << endl;
    cout << "-->" << gt_result << endl;
    gt_output.Check(P);


    // g1 processing units ====================
    typedef T<G1Element> g1Share;

    MascotEcPrep<g1Share, scalarShare> g1_preprocessing(usage, preprocessing);
    
    typename g1Share::mac_key_type g1_mac_key;
    g1Share::read_or_generate_mac_key("", P, g1_mac_key);


    typename g1Share::Direct_MC g1_output(output.get_alphai());
    

    typename g1Share::Input g1_input(g1_output, g1_preprocessing, P);


    vector<g1Share> g1_inputs_shares[2];
    g1_input.reset_all(P);
    g1_input.add_from_all(g1val);
    g1_input.exchange();
    g1_inputs_shares[0].push_back(g1_input.finalize(0));
    g1_inputs_shares[1].push_back(g1_input.finalize(1));

    typename g1Share::clear g1_result;
    g1_output.init_open(P);
    g1_output.prepare_open(g1_inputs_shares[0][0]);
    g1_output.exchange(P);
    g1_result = g1_output.finalize_open();
    cout << "-->" << g1val << endl;
    cout << "-->" << g1_result << endl;
    g1_output.Check(P);


// 
    // EcBeaver<g1Share, scalarShare> ecprotocol(P);
    // ecprotocol.init(preprocessing, gt_output, output);
    // ============================================


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
    // g2_new(pk1);
    // g2_new(pk2);

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
    // cout << "ver aggregate" << endl;

    // // scalar multiplication
	// bn_t skbn;
    // bn_null(skbn);
    // bn_new(skbn);
    // SeededPRNG G;
    // P256Element::Scalar sk;
    // sk.randomize(G);
    // string skstr = bigint(sk).get_str();
    // cout << skstr << endl;
    // cout << skstr.c_str() << endl;
    // int sklen = skstr.size();
    // cout << sklen << endl;
    // cout << strlen(skstr.c_str()) << endl;
    // bn_read_str(skbn, skstr.c_str(), sklen, 10);
    // bn_print(skbn);
    // cout << "===================" << endl;

    // char * bnout = (char *)malloc(100 * sizeof(char));
    // bn_write_str(bnout, 100, skbn, 10);
    // printf("%s\n", bnout);

    // cout << "===================" << endl;
    // gt_t pairval;
    // gt_new(pairval);
    // gt_free(pairval);
    // gt_mul(pairval, pairval, pairval);
    // core_clean();


    // vector<PCIInput> pciinputs;
    // vector<PCIInput> generatedinputsA;
    // vector<PCIInput> generatedinputsB;
    // ClearInput<PCIInput> clearInput(P);
    // unsigned char* message = (unsigned char*)"this is a sample claim1"; // 23
    // unsigned char* message2 = (unsigned char*)"this is a sample claim2"; // 23

    // // Input generation , let P0 perform it
    // SeededPRNG G;
    // if (P.my_num() == 0){
    //     // Generate secret keys and signatures with them
    //     cout << "generating random keys and signatures" << endl;
    //     P256Element::Scalar sk;

        
    //     for (int i = 0; i < TOTAL_GENERATED_INPUTS; i++)
    //     {
    //         // chose random sk
    //         sk.randomize(G);
    //         // create pk
    //         P256Element Pk(sk);

    //         // sign1
    //         EcSignature signature = sign(message, 23, sk);
    //         check(signature, message, 23, Pk);
    //         generatedinputsA.push_back({Pk, signature});

    //         // sign2
    //         EcSignature signature2 = sign(message2, 23, sk);
    //         check(signature2, message2, 23, Pk);
    //         generatedinputsB.push_back({Pk, signature2});
    //     }


    //     cout << "distributing input keys and signatures" << endl;
        
    //     for (int i = 0; i < INPUTSIZE; i++){
    //         pciinputs.push_back(generatedinputsA[i]);
    //         cout << pciinputs[i].Pk << pciinputs[i].signature.R << endl;
    //     }


    //     clearInput.reset_all();
    //     for (int i = secondPlayerInputIdx; i < TOTAL_GENERATED_INPUTS; i++){
    //         clearInput.add_mine(generatedinputsB[i]);
    //     }
    //     clearInput.exchange();
    // }

    // if (P.my_num() == 1){
    //     clearInput.reset_all();
    //     for (int i = 0; i < INPUTSIZE; i++)
    //     {
    //         clearInput.add_other(0);
    //     }
    //     clearInput.exchange();
    //     for (int i = 0; i < INPUTSIZE; i++)
    //     {
    //         pciinputs.push_back(clearInput.finalize(0));
    //         cout << pciinputs[i].Pk << pciinputs[i].signature.R << endl;
    //     }
    // }

    // cout << "==========  Input generation done ============" << endl;
    // Timer timer;
    // timer.start();
    // auto stats = P.total_comm();


    // DataPositions usage(P.num_players());

    // typedef T<P256Element::Scalar> scalarShare;

    // typename scalarShare::mac_key_type mac_key;
    // scalarShare::read_or_generate_mac_key("", P, mac_key);

    // typename scalarShare::Direct_MC output(mac_key);

    // typename scalarShare::LivePrep preprocessing(0, usage);
    
    // SubProcessor<scalarShare> processor(output, preprocessing, P);

    // typename scalarShare::Input input(output, preprocessing, P);


    // // Input Shares
    // cout <<  "------ Input ra_i and sa_i_inv ----------" << endl;
    // int thisplayer = N.my_num();
    // vector<scalarShare> r_share[2];
    // vector<scalarShare> s_inv_share[2];


    // // Give Input
    // input.reset_all(P);
    // for (int i = 0; i < INPUTSIZE; i++)
    //     {
    //         input.add_from_all(pciinputs[i].signature.R.x());
    //         input.add_from_all(pciinputs[i].signature.s.invert());
    //     }
    // input.exchange();
    // for (int i = 0; i < INPUTSIZE; i++)
    // {
    //     // shares of party A
    //     r_share[0].push_back(input.finalize(0));
    //     s_inv_share[0].push_back(input.finalize(0));

    //     // shares of party B
    //     r_share[1].push_back(input.finalize(1));
    //     s_inv_share[1].push_back(input.finalize(1));
    // }
    // cout << "---- scalar inputs shared ----" << thisplayer << endl;


    // // ------------------------------------------------------

    // cout <<  "------ Input Ra_i and Pk_i ----------" << endl;


    // typedef T<P256Element> ecShare;

    // typename ecShare::mac_key_type ec_mac_key;
    // ecShare::read_or_generate_mac_key("", P, ec_mac_key);


    // typename ecShare::Direct_MC ec_output(output.get_alphai());
    
    // MascotEcPrep<ecShare, scalarShare> ec_preprocessing(usage, preprocessing);

    // typename ecShare::Input ec_input(ec_output, ec_preprocessing, P);

    // EcBeaver<ecShare, scalarShare> ecprotocol(P);
    // ecprotocol.init(preprocessing, ec_output, output);

    // // Input Shares
    // vector<ecShare> R_share[2];
    // vector<ecShare> Pk_share[2];


    // // Give Input
    // ec_input.reset_all(P);
    // for (int i = 0; i < INPUTSIZE; i++){
    //     ec_input.add_from_all(pciinputs[i].signature.R);
    //     ec_input.add_from_all(pciinputs[i].Pk);
    // }
    // ec_input.exchange();
    // for (int i = 0; i < INPUTSIZE; i++)
    // {
    //     // shares of party A
    //     R_share[0].push_back(ec_input.finalize(0));
    //     Pk_share[0].push_back(ec_input.finalize(0));

    //     // shares of party B
    //     R_share[1].push_back(ec_input.finalize(1));
    //     Pk_share[1].push_back(ec_input.finalize(1));
    // }
    // cout << "---- ec inputs shared ----" << thisplayer << endl;

    // auto tinput = timer.elapsed();
    // cout << "Input sharing took " << tinput * 1e3 << " ms" << endl;


    // cout << " -------- compute ua1 ub1-----------" << endl;
    // vector<scalarShare> u1_share[2];
    // vector<scalarShare> u2_share[2];

    // P256Element::Scalar m[2];
    // m[0] = hash_to_scalar(message, 23);
    // m[1] = hash_to_scalar(message2, 23);

    // for (int i = 0; i < INPUTSIZE; i++){
    //     // u1_a
    //     u1_share[0].push_back(s_inv_share[0][i] * m[0]);
    //     // u1_b
    //     u1_share[1].push_back(s_inv_share[1][i] * m[1]);
    // }

    // cout << " -------- compute ua2, ub2-----------" << endl;
    // // ua2_i, ub2
    // processor.protocol.init_mul();
    // for (int i = 0; i < INPUTSIZE; i++){
    //     processor.protocol.prepare_mul(r_share[0][i], s_inv_share[0][i]);
    //     processor.protocol.prepare_mul(r_share[1][i], s_inv_share[1][i]);
    // }
    // processor.protocol.exchange();
    // for (int i = 0; i < INPUTSIZE; i++){
    //     u2_share[0].push_back(processor.protocol.finalize_mul());
    //     u2_share[1].push_back(processor.protocol.finalize_mul());
    // }

    // auto tu = timer.elapsed();
    // cout << "Computing u1 u2 took " << (tu - tinput) * 1e3 << " ms" << endl;


    // cout << " -------- Main loop -----------" << endl;
    // vector<ecShare> c_valid[2], c_right[2], c_final, c_final_randomized;
    // ecprotocol.init_mul();
    // for (int i = 0; i < INPUTSIZE; i++){
    //     ecprotocol.prepare_scalar_mul(u2_share[0][i], Pk_share[0][i]);
    //     ecprotocol.prepare_scalar_mul(u2_share[1][i], Pk_share[1][i]);
    // }
    // ecprotocol.exchange();
    // for (int i = 0; i < INPUTSIZE; i++){
    //     c_right[0].push_back(ecprotocol.finalize_mul());
    //     c_right[1].push_back(ecprotocol.finalize_mul());
    // }


    // for (int i = 0; i < INPUTSIZE; i++){
    //     c_valid[0].push_back(c_right[0][i] + u1_share[0][i] - R_share[0][i]);
    //     c_valid[1].push_back(c_right[1][i] + u1_share[1][i] - R_share[1][i]);
    // }

    // for (int i = 0; i < INPUTSIZE; i++){
    //     for (int j = 0; j < INPUTSIZE; j++){
    //         c_final.push_back(c_valid[0][i] + c_valid[1][j] + (Pk_share[0][i] - Pk_share[1][j]));
    //     }
    // }

    // auto tc = timer.elapsed();
    // cout << "Computing C' took " << (tc - tu) * 1e3 << " ms" << endl;

    
    // ecprotocol.init_mul();
    // // randomize c_final
    // cout << "generate randoms" << endl;
    // vector<scalarShare> myrandomshares;
    // scalarShare __;
    // for (int i = 0; i < INPUTSIZE; i++){
    //     for (int j = 0; j < INPUTSIZE; j++){
    //         typename scalarShare::clear tmp;
    //         myrandomshares.push_back({});
    //         preprocessing.get_two(DATA_INVERSE, myrandomshares.back(), __);
    //         ecprotocol.prepare_scalar_mul(myrandomshares.back(), c_final[INPUTSIZE*i + j]);;
    //     }
    // }
    // cout << "-- done --" << endl;

    // ecprotocol.exchange();
    // ec_output.init_open(P);
    // for (int i = 0; i < INPUTSIZE; i++){
    //     for (int j = 0; j < INPUTSIZE; j++){
    //         c_final_randomized.push_back(ecprotocol.finalize_mul());
    //         ec_output.prepare_open(c_final_randomized.back());
    //     }
    // }

    // vector<typename ecShare::clear> condition_result[INPUTSIZE];
    // ec_output.exchange(P);
    // for (int i = 0; i < INPUTSIZE; i++){
    //     for (int j = 0; j < INPUTSIZE; j++){
    //         condition_result[i].push_back(ec_output.finalize_open());
    //     }
    // }
    // ec_output.Check(P);

    // ec_output.init_open(P);
    // P256Element O;
    // for (int i = 0; i < INPUTSIZE; i++){
    //     for (int j = 0; j < INPUTSIZE; j++){
    //         if(condition_result[i][j] == O){
    //             ec_output.prepare_open(Pk_share[0][i]);
    //         }
    //     }
    // }
    // ec_output.exchange(P);
    // vector<typename ecShare::clear> pci_result;
    // for (int i = 0; i < INPUTSIZE; i++){
    //     for (int j = 0; j < INPUTSIZE; j++){
    //         if(condition_result[i][j] == O){
    //             pci_result.push_back(ec_output.finalize_open());
    //             cout << pci_result.back() << endl;
    //         }
    //     }
    // }
    // ec_output.Check(P);

    // cout << "Final time' " << timer.elapsed() * 1e3 << " ms" << endl;
    // (P.total_comm() - stats).print(true);


    // return;

    
}
