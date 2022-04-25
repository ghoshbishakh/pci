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
#include "Protocols/fake-stuff.hpp"
#include "Protocols/MascotPrep.hpp"
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
 
        pciinputs.push_back({sk, Pk, signature});
    }


    DataPositions usage(P.num_players());

    typedef T<P256Element::Scalar> scalarShare;

    typename scalarShare::mac_key_type mac_key;
    scalarShare::read_or_generate_mac_key("", P, mac_key);

    typename scalarShare::MAC_Check output(mac_key);

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

    // -----------------
}
