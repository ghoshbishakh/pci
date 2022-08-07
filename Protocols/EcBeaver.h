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
    void prepare_scalar_mul_parallel(thread_pool &pool, const vector<V>& x, const vector<T>& Y, int inputsize, int n = -1);

    void exchange();
    T finalize_mul(int n = -1);
    void finalize_mul(int count, thread_pool &pool, vector<T>& resvec);

    void check();

    void start_exchange();
    void stop_exchange();

    int get_n_relevant_players() { return 1 + T::threshold(P.num_players()); }
};
#endif /* PROTOCOLS_ECBEAVER_H_ */
