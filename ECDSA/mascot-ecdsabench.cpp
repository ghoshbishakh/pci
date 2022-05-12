/*
 * fake-spdz-bls-party.cpp
 *
 */

#define NO_MIXED_CIRCUITS

#define NO_SECURITY_CHECK

#include "GC/TinierSecret.h"
#include "GC/TinyMC.h"
#include "GC/VectorInput.h"

#include "Protocols/Share.hpp"
#include "Protocols/MAC_Check.hpp"
#include "GC/Secret.hpp"
#include "GC/TinierSharePrep.hpp"
#include "ot-ecdsa-party.hpp"

#include <assert.h>
#include "Math/gfp.h"
#include "ECDSA/P256Element.h"

int main(int argc, const char** argv)
{

    (void) argc;
    (void) argv;
    // Initialize curve and field
    // Initializes the field order to same as curve order 
    P256Element::init();
    // Initialize scalar:next with same order as field order. ??
    P256Element::Scalar::next::init_field(P256Element::Scalar::pr(), false);
    SeededPRNG G;

    int REPEAT = 6;
    int TIME = 1;

    long int opcount = 0;
    RunningTimer timer;
    timer.reset();


    // P256 Add
    P256Element P1, P2;

    P1.randomize(G);
    P2.randomize(G);
    for (int repeat = 0; repeat < REPEAT; repeat++)
    {
        timer.reset();
        opcount = 0;
        while (1)
        {
            P1 = P1 + P2;
            opcount++;
            if (timer.elapsed() > TIME){
                cout << "OPENSSL EC add," << opcount << "," << timer.elapsed() << endl;
                break;
            }
        }
    }

    // P256 Scalar Mul
    P256Element::Scalar x;
    x.randomize(G);
    for (int repeat = 0; repeat < REPEAT; repeat++)
    {
        timer.reset();
        opcount = 0;
        while (1)
        {
            P1 = x * P2;
            opcount++;
            if (timer.elapsed() > TIME){
                cout << "OPENSSL EC mul," << opcount << "," << timer.elapsed() << endl;
                break;
            }
        }
    }
}
