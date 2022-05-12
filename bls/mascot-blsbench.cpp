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
#include "ot-bls-party.hpp"

#include <assert.h>

extern "C" {
#include <relic/relic_core.h>
#include <relic/relic_bn.h>
#include <relic/relic_pc.h>
#include <relic/relic_cp.h>
}


int main(int argc, const char** argv)
{
    (void) argc;
    (void) argv;
    int REPEAT = 6;
    int TIME = 1;
    // INIT RELIC
    if (core_init() != RLC_OK) {
        core_clean();
        return 1;
    }


    RunningTimer timer;
    long int opcount = 0;
    timer.reset();

    // ------------------ ec operations --------------------------
    assert(ec_param_set_any() == RLC_OK);
    ec_param_print();

    ec_t ec1, ec2;
    ec_null(ec1);
    ec_null(ec2);
    ec_new(ec1);
    ec_new(ec2);
    ec_rand(ec1);
    ec_rand(ec2);


    for (int repeat = 0; repeat < REPEAT; repeat++)
    {
        timer.reset();
        opcount = 0;
        while (1)
        {
            ec_add(ec1, ec1, ec2);
            opcount++;
            if (timer.elapsed() > TIME){
                cout << "BLS EC EC add," << opcount << "," << timer.elapsed() << endl;
                break;
            }
        }
    }

    ec_free(ec1);
    ec_free(ec2);

    // ---------------- ec mul --------------------------
    ec_null(ec1);
    ec_new(ec1);
    ec_rand(ec1);


    bn_t bnval, n;
    bn_null(bnval);
    bn_null(n);
    bn_new(bnval);
    bn_new(n);
	ec_curve_get_ord(n);

bn_rand_mod(bnval, n);
                ec_mul(ec1, ec1, bnval);


    for (int repeat = 0; repeat < REPEAT; repeat++)
    {
        timer.reset();
        opcount = 0;
        while (1)
        {
            ec_mul(ec1, ec1, bnval);
            opcount++;
            if (timer.elapsed() > TIME){
                cout << "BLS EC EC mul," << opcount << "," << timer.elapsed() << endl;
                break;
            }
        }
    }
    ec_free(ec1);


    bn_free(bnval);


// ------------

    // assert(pc_param_set_any() == RLC_OK);
    // pc_param_print();
    // // -------------------- g1 add ---------------
    // g1_t g1val, g1val2;
    // g1_null(g1val);
    // g1_null(g1val2);
    // g1_new(g1val);
    // g1_new(g1val2);
    // g1_rand(g1val);
    // g1_rand(g1val2);

    // for (int repeat = 0; repeat < REPEAT; repeat++)
    // {
    //     timer.reset();
    //     opcount = 0;
    //     while (1)
    //     {
    //         g1_add(g1val, g1val, g1val2);
    //         opcount++;
    //         if (timer.elapsed() > TIME){
    //             cout << "BLS EC G1 add," << opcount << "," << timer.elapsed() << endl;
    //             break;
    //         }
    //     }
    // }
    // g1_free(g1val);
    // g1_free(g1val2);

    // // ---------------------- g2 add ----------------------
    // g2_t g2val, g2val2;
    // g2_null(g2val);
    // g2_null(g2val2);
    // g2_new(g2val);
    // g2_new(g2val2);
    // g2_rand(g2val);
    // g2_rand(g2val2);


    // for (int repeat = 0; repeat < REPEAT; repeat++)
    // {
    //     timer.reset();
    //     opcount = 0;
    //     while (1)
    //     {
    //         g2_add(g2val, g2val, g2val2);
    //         opcount++;
    //         if (timer.elapsed() > TIME){
    //             cout << "BLS EC G2 add," << opcount << "," << timer.elapsed() << endl;
    //             break;
    //         }
    //     }
    // }
    // g2_free(g2val);
    // g2_free(g2val2);

    // // ------------------ g1 mul --------------------------

    // g1_t g1element;
    // g1_null(g1element);
    // g1_new(g1element);
    // g1_rand(g1element);
    
    // bn_t(bnval);
    // bn_null(bnval);
    // bn_new(bnval);
    // bn_rand(bnval, RLC_POS, RLC_BN_BITS);

    // for (int repeat = 0; repeat < REPEAT; repeat++)
    // {
    //     timer.reset();
    //     opcount = 0;
    //     while (1)
    //     {
    //         g1_mul(g1element, g1element, bnval);
    //         opcount++;
    //         if (timer.elapsed() > TIME){
    //             cout << "BLS EC G1 mul," << opcount << "," << timer.elapsed() << endl;
    //             break;
    //         }
    //     }
    // }
    // g2_free(g1element);
    // bn_free(bnval);

    // // ------------------ g2 mul --------------------------

    // g2_t g2element;
    // g2_null(g2element);
    // g2_new(g2element);
    // g2_rand(g2element);
    
    // bn_null(bnval);
    // bn_new(bnval);
    // bn_rand(bnval, RLC_POS, RLC_BN_BITS);

    // for (int repeat = 0; repeat < REPEAT; repeat++)
    // {
    //     timer.reset();
    //     opcount = 0;
    //     while (1)
    //     {
    //         g2_mul(g2element, g2element, bnval);
    //         opcount++;
    //         if (timer.elapsed() > TIME){
    //             cout << "BLS EC G2 mul," << opcount << "," << timer.elapsed() << endl;
    //             break;
    //         }
    //     }
    // }
    // g2_free(g2element);
    // bn_free(bnval);

    // // ------------------ pair g1 g2 --------------------------

    // g2_null(g2element);
    // g2_new(g2element);
    // g2_rand(g2element);
    // g1_null(g1element);
    // g1_new(g1element);
    // g1_rand(g1element);

    // gt_t gtelement;
    // gt_null(gtelement);
    // gt_new(gtelement);
    

    // for (int repeat = 0; repeat < REPEAT; repeat++)
    // {
    //     timer.reset();
    //     opcount = 0;
    //     while (1)
    //     {
    //         pc_map(gtelement, g1element, g2element);
    //         opcount++;
    //         if (timer.elapsed() > TIME){
    //             cout << "BLS EC PAIR G1 G2," << opcount << "," << timer.elapsed() << endl;
    //             break;
    //         }
    //     }
    // }
    // g2_free(g2element);
    // g1_free(g1element);
    // gt_free(gtelement);



    core_clean();

}
