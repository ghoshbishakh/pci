/*
 * Beaver.h
 *
 */

#ifndef PROTOCOLS_ECBEAVER_H_
#define PROTOCOLS_ECBEAVER_H_

#include <vector>
#include <array>
using namespace std;

#include "Replicated.h"
#include "Processor/Data_Files.h"
#include "../bls/thread_pool.hpp"

extern "C" {
#include <relic/relic_core.h>
#include <relic/relic_bn.h>
#include <relic/relic_pc.h>
#include <relic/relic_cp.h>
}



/**
 * Beaver multiplication for EC
 */
// T = Share<P256>, V = Share<gfp>
template<class T, class V>
class EcBeaver : public ProtocolBase<T>
{
protected:
    vector<T> sharesEc;
    vector<V> sharesScalar;
    vector<typename T::open_type> openedEc;
    vector<typename V::open_type> openedScalar;
    vector<array<V, 3>> triples;
    typename vector<typename T::open_type>::iterator itEc;
    typename vector<typename V::open_type>::iterator itScalar;
    typename vector<array<V, 3>>::iterator triple;
    Preprocessing<V>* prep;
    typename T::MAC_Check* MCec;
    typename V::MAC_Check* MCscalar;

public:
    static const bool uses_triples = true;

    Player& P;

    EcBeaver(Player& P) : prep(0), MCec(0), MCscalar(0), P(P) {}

    typename T::Protocol branch();

    void init(Preprocessing<V>& prep, typename T::MAC_Check& MCec, typename V::MAC_Check& MCscalar);

    static void ecscalarmulshare(typename T::open_type::Scalar multiplier, T pointshare, T& result);
    static void ecscalarmulshare(V multiplierShare, typename T::open_type point, T& result);

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void prepare_scalar_mul(const V& x, const T& Y, int n = -1);
    void exchange();
    T finalize_mul(int n = -1);
    void finalize_mul(int count, thread_pool &pool, vector<T>& resvec);

    void check();

    void start_exchange();
    void stop_exchange();

    int get_n_relevant_players() { return 1 + T::threshold(P.num_players()); }
};


/**
 * Beaver multiplication for EC
 */
// T = Share<Gt>, V = Share<gfp>
template<class T, class G1, class G2, class V>
class PairBeaver : public ProtocolBase<T>
{
protected:
    vector<G1> sharesG1;
    vector<G2> sharesG2;
    vector<typename G1::open_type> openedG1;
    vector<typename G2::open_type> openedG2;
    vector<array<V, 3>> triples;
    typename vector<typename G1::open_type>::iterator itG1;
    typename vector<typename G2::open_type>::iterator itG2;
    typename vector<array<V, 3>>::iterator triple;
    Preprocessing<V>* prep;
    typename T::MAC_Check* MCec;
    typename V::MAC_Check* MCscalar;
    typename G1::MAC_Check* MCg1;
    typename G2::MAC_Check* MCg2;

public:
    static const bool uses_triples = true;

    Player& P;

    PairBeaver(Player& P) : prep(0), MCec(0), MCscalar(0), MCg1(0), MCg2(0), P(P) {}

    typename T::Protocol branch();

    void init(Preprocessing<V>& prep,
              typename T::MAC_Check& MCec,
              typename V::MAC_Check& MCscalar,
              typename G1::MAC_Check& MCg1,
              typename G2::MAC_Check& MCg2);

    void init_pair();
    void prepare_pair(const G1& X, const G2& Y, int n = -1);
    void exchange();
    T finalize_pair(int n = -1);
    void finalize_pair(int count, thread_pool &pool, vector<T>& resvec);

    void check();
    static T pair_g1share_p(G1 g1shareip);
    static T pair_g1_g2share(typename G1::open_type g1ip, G2 g2share);
    static T pair_g1share_g2(G1 g1share, typename G2::open_type g2ip);
    void start_exchange();
    void stop_exchange();

    void init_mul(){ throw not_implemented(); };
    void prepare_mul(const T& x, const T& y, int n = -1){ (void) x; (void) y; (void) n; throw not_implemented(); };
    T finalize_mul(int n = -1){ (void) n; throw not_implemented();};


    int get_n_relevant_players() { return 1 + T::threshold(P.num_players()); }
};



#endif /* PROTOCOLS_ECBEAVER_H_ */
