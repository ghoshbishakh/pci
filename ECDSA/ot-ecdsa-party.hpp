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
    P256Element::Scalar sk;
    P256Element Pk;
    EcSignature signature;
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

    
    // Generate secret keys and signatures with them
    cout << "generating random keys and signatures" << endl;
    vector<PCIInput> pciinputs;
    P256Element::Scalar sk;

    SeededPRNG G;
    int INPUTSIZE = 3;
    unsigned char* message = (unsigned char*)"this is a sample claim"; // 22
    
    for (int i = 0; i < INPUTSIZE; i++)
    {
        // chose random sk
        sk.randomize(G);

        // create pk
        P256Element Pk(sk);

        // sign
        EcSignature signature = sign(message, 22, sk);
        check(signature, message, 22, Pk);
 
        pciinputs.push_back({sk, Pk, signature});
    }


    DataPositions usage(P.num_players());

    typedef T<P256Element::Scalar> scalarShare;

    typename scalarShare::mac_key_type mac_key;
    scalarShare::read_or_generate_mac_key("", P, mac_key);

    typename scalarShare::Direct_MC output(mac_key);

    typename scalarShare::LivePrep preprocessing(0, usage);
    
    SubProcessor<scalarShare> processor(output, preprocessing, P);

    typename scalarShare::Input input(output, preprocessing, P);


    // Input Shares
    int thisplayer = N.my_num();
    vector<scalarShare> inputs_shares[2];


    // Give Input
    // typename scalarShare::Input input = protocolSet.input;

    input.reset_all(P);
    for (int i = 0; i < INPUTSIZE; i++)
        input.add_from_all(pciinputs[i].sk);
    input.exchange();
    for (int i = 0; i < INPUTSIZE; i++)
    {
        // shares of party A
        inputs_shares[0].push_back(input.finalize(0));

        // shares of party B
        inputs_shares[1].push_back(input.finalize(1));
    }
    cout << "---- inputs shared ----" << thisplayer << endl;

    // output
    typename scalarShare::clear result;
    // auto& output = protocolSet.output;
    output.init_open(P);
    output.prepare_open(inputs_shares[0][0]);
    output.exchange(P);
    result = output.finalize_open();
    cout << "-->" << pciinputs[0].sk << endl;
    cout << "-->" << result << endl;
    output.Check(processor.P);

    // ------------------------------------------------------

    typedef T<P256Element> ecShare;

    typename ecShare::mac_key_type ec_mac_key;
    ecShare::read_or_generate_mac_key("", P, ec_mac_key);


    typename ecShare::Direct_MC ec_output(output.get_alphai());
    
    MascotEcPrep<ecShare, scalarShare> ec_preprocessing(usage, preprocessing);

    // SubProcessor<ecShare> ec_processor(ec_output, ec_preprocessing, P);

    typename ecShare::Input ec_input(ec_output, ec_preprocessing, P);


    // Input Shares
    vector<ecShare> ec_inputs_shares[2];


    // Give Input
    // typename ecShare::Input input = protocolSet.input;

    ec_input.reset_all(P);
    for (int i = 0; i < INPUTSIZE; i++)
        ec_input.add_from_all(pciinputs[i].Pk);
    ec_input.exchange();
    for (int i = 0; i < INPUTSIZE; i++)
    {
        // shares of party A
        ec_inputs_shares[0].push_back(ec_input.finalize(0));

        // shares of party B
        ec_inputs_shares[1].push_back(ec_input.finalize(1));
    }
    cout << "---- ec inputs shared ----" << thisplayer << endl;

    // output
    typename ecShare::clear ec_result;
    ec_output.init_open(P);
    ec_output.prepare_open(ec_inputs_shares[0][0]);
    ec_output.exchange(P);
    ec_result = ec_output.finalize_open();
    cout << "-->" << pciinputs[0].Pk << endl;
    cout << "-->" << ec_result << endl;
    ec_output.Check(P);

    cout << "---- Add-G ----" << thisplayer << endl;
    // Multiply open scalar- result with private point ec_inputs_shares[0][1]

    if (P.my_num() == 0){
        cout << "Expected result of Add-G: " << pciinputs[1].Pk + pciinputs[1].Pk << endl;
    }

    ecShare addgs = ec_inputs_shares[0][1] + ec_inputs_shares[0][1];
    ec_output.init_open(P);
    ec_output.prepare_open(addgs);
    ec_output.exchange(P);
    ec_result = ec_output.finalize_open();
    cout << "-->" << ec_result << endl;
    ec_output.Check(P);

    cout << "---- Multiply-G-P ----" << thisplayer << endl;
    if (P.my_num() == 0){
        cout << "Expected result of Multiply-G-P: " << pciinputs[1].Pk * result << endl;
    }

    ecShare mulgp = {};
    ecscalarmulshare(ec_inputs_shares[0][1], result, mulgp);
    ec_output.init_open(P);
    ec_output.prepare_open(mulgp);
    ec_output.exchange(P);
    ec_result = ec_output.finalize_open();
    cout << "-->" << ec_result << endl;
    ec_output.Check(P);

    cout << "---- Multiply-G-P-dash [<x>]P ----" << thisplayer << endl;
    if (P.my_num() == 0){
        cout << "Expected result of Multiply-G-P: " << ec_result * pciinputs[1].sk << endl;
    }

    ecShare mulgp2 = {};
    ecscalarmulshare(ec_result, inputs_shares[0][1], mulgp2);
    ec_output.init_open(P);
    ec_output.prepare_open(mulgp2);
    ec_output.exchange(P);
    ec_result = ec_output.finalize_open();
    cout << "-->" << ec_result << endl;
    ec_output.Check(P);

    // EcBeaver<ecShare, scalarShare> ecprotocol(P);


    cout << "---- Multiply-G-S ----" << thisplayer << endl;
    if (P.my_num() == 0){
        cout << "Expected result of Multiply-G-S: " << pciinputs[1].Pk * pciinputs[1].sk << endl;
    }

    EcBeaver<ecShare, scalarShare> ecprotocol(P);
    ecprotocol.init(preprocessing, ec_output, output);
    ecprotocol.init_mul();
    ecprotocol.prepare_scalar_mul(inputs_shares[0][1], ec_inputs_shares[0][1]);
    ecprotocol.exchange();
    ecShare ec_result_share = ecprotocol.finalize_mul();
    
    ec_output.init_open(P);
    ec_output.prepare_open(ec_result_share);
    ec_output.exchange(P);
    ec_result = ec_output.finalize_open();
    cout << "-->" << ec_result << endl;
    ec_output.Check(P);




    cout << "=====================" << endl;
    
}
