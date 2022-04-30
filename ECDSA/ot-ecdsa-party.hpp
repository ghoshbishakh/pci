/*
 * fake-spdz-ecdsa-party.cpp
 *
 */

#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Math/gfp.h"
#include "ECDSA/P256Element.h"
#include "Protocols/SemiShare.h"
#include "Processor/BaseMachine.h"

#include "ECDSA/preprocessing.hpp"
#include "ECDSA/sign.hpp"
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
    EcdsaOptions opts(opt, argc, argv);
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

    int INPUTSIZE = 100;
    int COMMON = 2;
    int TOTAL_GENERATED_INPUTS = INPUTSIZE*2 - COMMON;
    int secondPlayerInputIdx = INPUTSIZE - COMMON;

    OnlineOptions::singleton.batch_size = 10 * INPUTSIZE;


    // Setup network with two players
    Names N(opt, argc, argv, 2);

    // Setup PlainPlayer
    PlainPlayer P(N, "ecdsa");
    
    // Initialize curve and field
    // Initializes the field order to same as curve order 
    P256Element::init();
    // Initialize scalar:next with same order as field order. ??
    P256Element::Scalar::next::init_field(P256Element::Scalar::pr(), false);
    
    BaseMachine machine;
    machine.ot_setups.push_back({P, true});


    vector<PCIInput> pciinputs;
    vector<PCIInput> generatedinputsA;
    vector<PCIInput> generatedinputsB;
    ClearInput<PCIInput> clearInput(P);
    unsigned char* message = (unsigned char*)"this is a sample claim1"; // 23
    unsigned char* message2 = (unsigned char*)"this is a sample claim2"; // 23

    // Input generation , let P0 perform it
    SeededPRNG G;
    if (P.my_num() == 0){
        // Generate secret keys and signatures with them
        cout << "generating random keys and signatures" << endl;
        P256Element::Scalar sk;

        
        for (int i = 0; i < TOTAL_GENERATED_INPUTS; i++)
        {
            // chose random sk
            sk.randomize(G);
            // create pk
            P256Element Pk(sk);

            // sign1
            EcSignature signature = sign(message, 23, sk);
            check(signature, message, 23, Pk);
            generatedinputsA.push_back({Pk, signature});

            // sign2
            EcSignature signature2 = sign(message2, 23, sk);
            check(signature2, message2, 23, Pk);
            generatedinputsB.push_back({Pk, signature2});
        }


        cout << "distributing input keys and signatures" << endl;
        
        for (int i = 0; i < INPUTSIZE; i++){
            pciinputs.push_back(generatedinputsA[i]);
            cout << pciinputs[i].Pk << pciinputs[i].signature.R << endl;
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
            cout << pciinputs[i].Pk << pciinputs[i].signature.R << endl;
        }
    }

    cout << "==========  Input generation done ============" << endl;
    Timer timer;
    timer.start();
    auto stats = P.total_comm();


    DataPositions usage(P.num_players());

    typedef T<P256Element::Scalar> scalarShare;

    typename scalarShare::mac_key_type mac_key;
    scalarShare::read_or_generate_mac_key("", P, mac_key);

    typename scalarShare::Direct_MC output(mac_key);

    typename scalarShare::LivePrep preprocessing(0, usage);
    
    SubProcessor<scalarShare> processor(output, preprocessing, P);

    typename scalarShare::Input input(output, preprocessing, P);


    // Input Shares
    cout <<  "------ Input ra_i and sa_i_inv ----------" << endl;
    int thisplayer = N.my_num();
    vector<scalarShare> r_share[2];
    vector<scalarShare> s_inv_share[2];


    // Give Input
    input.reset_all(P);
    for (int i = 0; i < INPUTSIZE; i++)
        {
            input.add_from_all(pciinputs[i].signature.R.x());
            input.add_from_all(pciinputs[i].signature.s.invert());
        }
    input.exchange();
    for (int i = 0; i < INPUTSIZE; i++)
    {
        // shares of party A
        r_share[0].push_back(input.finalize(0));
        s_inv_share[0].push_back(input.finalize(0));

        // shares of party B
        r_share[1].push_back(input.finalize(1));
        s_inv_share[1].push_back(input.finalize(1));
    }
    cout << "---- scalar inputs shared ----" << thisplayer << endl;


    // ------------------------------------------------------

    cout <<  "------ Input Ra_i and Pk_i ----------" << endl;


    typedef T<P256Element> ecShare;

    typename ecShare::mac_key_type ec_mac_key;
    ecShare::read_or_generate_mac_key("", P, ec_mac_key);


    typename ecShare::Direct_MC ec_output(output.get_alphai());
    
    MascotEcPrep<ecShare, scalarShare> ec_preprocessing(usage, preprocessing);

    typename ecShare::Input ec_input(ec_output, ec_preprocessing, P);

    EcBeaver<ecShare, scalarShare> ecprotocol(P);
    ecprotocol.init(preprocessing, ec_output, output);

    // Input Shares
    vector<ecShare> R_share[2];
    vector<ecShare> Pk_share[2];


    // Give Input
    ec_input.reset_all(P);
    for (int i = 0; i < INPUTSIZE; i++){
        ec_input.add_from_all(pciinputs[i].signature.R);
        ec_input.add_from_all(pciinputs[i].Pk);
    }
    ec_input.exchange();
    for (int i = 0; i < INPUTSIZE; i++)
    {
        // shares of party A
        R_share[0].push_back(ec_input.finalize(0));
        Pk_share[0].push_back(ec_input.finalize(0));

        // shares of party B
        R_share[1].push_back(ec_input.finalize(1));
        Pk_share[1].push_back(ec_input.finalize(1));
    }
    cout << "---- ec inputs shared ----" << thisplayer << endl;

    auto tinput = timer.elapsed();
    cout << "Input sharing took " << tinput * 1e3 << " ms" << endl;


    cout << " -------- compute ua1 ub1-----------" << endl;
    vector<scalarShare> u1_share[2];
    vector<scalarShare> u2_share[2];

    P256Element::Scalar m[2];
    m[0] = hash_to_scalar(message, 23);
    m[1] = hash_to_scalar(message2, 23);

    for (int i = 0; i < INPUTSIZE; i++){
        // u1_a
        u1_share[0].push_back(s_inv_share[0][i] * m[0]);
        // u1_b
        u1_share[1].push_back(s_inv_share[1][i] * m[1]);
    }

    cout << " -------- compute ua2, ub2-----------" << endl;
    // ua2_i, ub2
    processor.protocol.init_mul();
    for (int i = 0; i < INPUTSIZE; i++){
        processor.protocol.prepare_mul(r_share[0][i], s_inv_share[0][i]);
        processor.protocol.prepare_mul(r_share[1][i], s_inv_share[1][i]);
    }
    processor.protocol.exchange();
    for (int i = 0; i < INPUTSIZE; i++){
        u2_share[0].push_back(processor.protocol.finalize_mul());
        u2_share[1].push_back(processor.protocol.finalize_mul());
    }

    auto tu = timer.elapsed();
    cout << "Computing u1 u2 took " << (tu - tinput) * 1e3 << " ms" << endl;


    cout << " -------- Main loop -----------" << endl;
    vector<ecShare> c_valid[2], c_right[2], c_final, c_final_randomized;
    ecprotocol.init_mul();
    for (int i = 0; i < INPUTSIZE; i++){
        ecprotocol.prepare_scalar_mul(u2_share[0][i], Pk_share[0][i]);
        ecprotocol.prepare_scalar_mul(u2_share[1][i], Pk_share[1][i]);
    }
    ecprotocol.exchange();
    for (int i = 0; i < INPUTSIZE; i++){
        c_right[0].push_back(ecprotocol.finalize_mul());
        c_right[1].push_back(ecprotocol.finalize_mul());
    }


    for (int i = 0; i < INPUTSIZE; i++){
        c_valid[0].push_back(c_right[0][i] + u1_share[0][i] - R_share[0][i]);
        c_valid[1].push_back(c_right[1][i] + u1_share[1][i] - R_share[1][i]);
    }

    for (int i = 0; i < INPUTSIZE; i++){
        for (int j = 0; j < INPUTSIZE; j++){
            c_final.push_back(c_valid[0][i] + c_valid[1][j] + (Pk_share[0][i] - Pk_share[1][j]));
        }
    }

    auto tc = timer.elapsed();
    cout << "Computing C' took " << (tc - tu) * 1e3 << " ms" << endl;

    
    ecprotocol.init_mul();
    // randomize c_final
    cout << "generate randoms" << endl;
    vector<scalarShare> myrandomshares;
    scalarShare __;
    for (int i = 0; i < INPUTSIZE; i++){
        for (int j = 0; j < INPUTSIZE; j++){
            typename scalarShare::clear tmp;
            myrandomshares.push_back({});
            preprocessing.get_two(DATA_INVERSE, myrandomshares.back(), __);
            ecprotocol.prepare_scalar_mul(myrandomshares.back(), c_final[INPUTSIZE*i + j]);;
        }
    }
    cout << "-- done --" << endl;

    ecprotocol.exchange();
    ec_output.init_open(P);
    for (int i = 0; i < INPUTSIZE; i++){
        for (int j = 0; j < INPUTSIZE; j++){
            c_final_randomized.push_back(ecprotocol.finalize_mul());
            ec_output.prepare_open(c_final_randomized.back());
        }
    }

    vector<typename ecShare::clear> condition_result[INPUTSIZE];
    ec_output.exchange(P);
    for (int i = 0; i < INPUTSIZE; i++){
        for (int j = 0; j < INPUTSIZE; j++){
            condition_result[i].push_back(ec_output.finalize_open());
        }
    }
    ec_output.Check(P);

    ec_output.init_open(P);
    P256Element O;
    for (int i = 0; i < INPUTSIZE; i++){
        for (int j = 0; j < INPUTSIZE; j++){
            if(condition_result[i][j] == O){
                ec_output.prepare_open(Pk_share[0][i]);
            }
        }
    }
    ec_output.exchange(P);
    vector<typename ecShare::clear> pci_result;
    for (int i = 0; i < INPUTSIZE; i++){
        for (int j = 0; j < INPUTSIZE; j++){
            if(condition_result[i][j] == O){
                pci_result.push_back(ec_output.finalize_open());
                cout << pci_result.back() << endl;
            }
        }
    }
    ec_output.Check(P);

    cout << "Final time' " << timer.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - stats).print(true);


    return;

    
}
