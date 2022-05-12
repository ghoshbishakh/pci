/*
 * fake-spdz-bls-party-pair.cpp
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
    INPUTSIZE = 1000;
    opt.parse(argc, argv);
    OnlineOptions::singleton.batch_size = 10000;

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
    vector<G1Element> G1Arr;
    vector<G2Element> G2Arr;
    vector<GtElement> GtArr;

    G1Element g1tmp;
    G2Element g2tmp;
    G3Element gttmp;

    SeededPRNG G;
    cout << "generating random G1 G2" << endl;
    G1Element::Scalar sk;

    G1Element signature1, signature2;
    for (int i = 0; i < INPUTSIZE; i++)
    {
        g1tmp.randomize(G);
        g2tmp.randomize(G);
        gttmp = pair_g1_g2(g1tmp, g2tmp);

        G1Arr.push_back(g1tmp);
        G2Arr.push_back(g2tmp);
        GtArr.push_back(gttmp);
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


    cout <<  "------ Input G1 , G2  ----------" << endl;

    // Input Shares
    vector<g1Share> g1_shares[2];
    vector<g2Share> g2_shares[2];


    // Give Input
    g1_input.reset_all(P);
    g2_input.reset_all(P);
    for (int i = 0; i < INPUTSIZE; i++){
        g1_input.add_from_all(G1Arr[i]);
        g2_input.add_from_all(G1Arr[i]);
    }
    g1_input.exchange();
    g2_input.exchange();
    for (int i = 0; i < INPUTSIZE; i++)
    {
        // shares of party A
        g1_shares[0].push_back(g1_input.finalize(0));
        g2_shares[0].push_back(g2_input.finalize(0));

        // shares of party B
        g1_shares[1].push_back(g1_input.finalize(1));
        g2_shares[1].push_back(g2_input.finalize(1));

    }
    cout << "---- inputs shared ----" << N.my_num() << endl;

    auto tinput = timer.elapsed();
    cout << ">>>> Input sharing," << tinput * 1e3 << ", ms" << endl;


    // forget about shares from p1, work on shares from p0 only .. same thing

    cout << "---- computing pairings ----" << N.my_num() << endl;

    vector<gtShare> pairresults;
    gtShare tmp;

    gtprotocol.init_mul();
    for (int i = 0; i < INPUTSIZE; i++)
    {
        gtprotocol.prepare_pair(g1_shares[INPUTSIZE], g2_shares[INPUTSIZE]);
    }
    gtprotocol.exchange();
    for (int i = 0; i < INPUTSIZE; i++)
    {
      pairresults.push_back(gtprotocol.finalize_mul();
    }


    cout << ">>>> Final time," << timer.elapsed() * 1e3 << ", ms" << endl;
    (P.total_comm() - stats).print(true);


    
}
