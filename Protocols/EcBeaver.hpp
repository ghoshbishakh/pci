/*
 * EcBeaver.cpp
 *
 */

#ifndef PROTOCOLS_ECBEAVER_HPP_
#define PROTOCOLS_ECBEAVER_HPP_

#include "EcBeaver.h"

#include "Replicated.hpp"

#include <array>

template<class T, class V>
typename T::Protocol EcBeaver<T, V>::branch()
{
    typename T::Protocol res(P);
    res.prep = prep;
    res.MCec = MCec;
    res.MCscalar = MCscalar;
    res.init_mul();
    return res;
}

template<class T, class V>
void EcBeaver<T, V>::init(Preprocessing<V>& prep, typename T::MAC_Check& MCec, typename V::MAC_Check& MCscalar)
{
    this->prep = &prep;
    this->MCec = &MCec;
    this->MCscalar = &MCscalar;
}

template<class T, class V>
void EcBeaver<T, V>::init_mul()
{
    assert(this->prep);
    assert(this->MCec);
    assert(this->MCscalar);
    sharesEc.clear();
    sharesScalar.clear();
    openedEc.clear();
    openedScalar.clear();
    triples.clear();
}

template<class T, class V>
void EcBeaver<T, V>::prepare_mul(const T& x, const T& y, int n)
{ 
    (void) x;
    (void) y;
    (void) n;
    throw not_implemented(); 
}


template<class T, class V>
void EcBeaver<T, V>::prepare_scalar_mul(const V& x, const T& Y, int n)
{
    (void) n;
    triples.push_back({{}});
    auto& triple = triples.back();
    triple = prep->get_triple(n);
    sharesScalar.push_back(x - triple[0]);
    sharesEc.push_back(Y - triple[1]);
}

// [a]<G>
template<class T, class V>
void EcBeaver<T, V>::ecscalarmulshare(typename T::open_type::Scalar multiplier, T pointshare, T& result){
    result.set_share(pointshare.get_share() * multiplier);
    result.set_mac(pointshare.get_mac() * multiplier);
}

// [<a>]G
template<class T, class V>
void EcBeaver<T, V>::ecscalarmulshare(V multiplierShare, typename T::open_type point, T& result){
    result.set_share(point * multiplierShare.get_share());
    result.set_mac(point * multiplierShare.get_mac());
}

template<class T, class V>
void EcBeaver<T, V>::exchange()
{
    MCec->POpen(openedEc, sharesEc, P);
    MCscalar->POpen(openedScalar, sharesScalar, P);
    itEc = openedEc.begin();
    itScalar = openedScalar.begin();
    triple = triples.begin();
}

template<class T, class V>
void EcBeaver<T, V>::start_exchange()
{
    MCec->POpen_Begin(openedEc, sharesEc, P);
    MCscalar->POpen_Begin(openedScalar, sharesScalar, P);
}

template<class T, class V>
void EcBeaver<T, V>::stop_exchange()
{
    MCec->POpen_End(openedEc, sharesEc, P);
    MCscalar->POpen_End(openedScalar, sharesScalar, P);
    itEc = openedEc.begin();
    itScalar = openedScalar.begin();
    triple = triples.begin();
}

template<class T, class V>
T EcBeaver<T, V>::finalize_mul(int n)
{
    (void) n;
    typename V::open_type maskedScalar; // epsilon
    typename T::open_type maskedEc; // D

    V& a = (*triple)[0];
    T C = (*triple)[2];
    T B = (*triple)[1];
    T tmpec = {};

    maskedScalar = *itScalar;
    maskedEc = *itEc;

    ecscalarmulshare(maskedScalar, B, tmpec);
    C += tmpec;
    ecscalarmulshare(a, maskedEc, tmpec);
    C += tmpec;
    C += T::constant(maskedEc * maskedScalar, P.my_num(), MCec->get_alphai());
    triple++;
    itScalar++;
    itEc++;
    return C;
}

// PARALLEL FINALIZE MUL
template<class T, class V>
void EcBeaver<T, V>::finalize_mul(int count, thread_pool &pool, vector<T>& resvec)
{
    resvec.resize(count);
    auto mynum_ = P.my_num();
    for (int i = 0; i < count; i++)
    {
        typename V::open_type maskedScalar; // epsilon
        typename T::open_type maskedEc; // D

        V& a = (*triple)[0];
        T C = (*triple)[2];
        T B = (*triple)[1];
        maskedScalar = *itScalar;
        maskedEc = *itEc;
        auto alphai = MCec->get_alphai();

        pool.push_task([&resvec, i, maskedScalar, B, C, a, maskedEc, mynum_, alphai]{
            T tmpres = C;
            T tmpec = {};
            ecscalarmulshare(maskedScalar, B, tmpec);
            tmpres += tmpec;
            ecscalarmulshare(a, maskedEc, tmpec);
            tmpres += tmpec;
            tmpres += T::constant(maskedEc * maskedScalar, mynum_, alphai);
            resvec[i] = tmpres;
        });

        triple++;
        itScalar++;
        itEc++;
    }

    pool.wait_for_tasks();
}

template<class T, class V>
void EcBeaver<T, V>::check()
{
    assert(MCec);
    assert(MCscalar);
    MCec->Check(P);
    MCscalar->Check(P);
}









// ---------------------------------------------------




template<class T, class G1, class G2, class V>
typename T::Protocol PairBeaver<T, G1, G2, V>::branch()
{
    typename T::Protocol res(P);
    res.prep = prep;
    res.MCec = MCec;
    res.MCscalar = MCscalar;
    res.init_mul();
    return res;
}

template<class T, class G1, class G2, class V>
void PairBeaver<T, G1, G2, V>::init(Preprocessing<V>& prep, typename T::MAC_Check& MCec, typename V::MAC_Check& MCscalar)
{
    this->prep = &prep;
    this->MCec = &MCec;
    this->MCscalar = &MCscalar;
}

template<class T, class G1, class G2, class V>
void PairBeaver<T, G1, G2, V>::init_mul()
{
    assert(this->prep);
    assert(this->MCec);
    assert(this->MCscalar);
    sharesGt.clear();
    sharesScalar.clear();
    openedEc.clear();
    openedScalar.clear();
    triples.clear();
}

template<class T, class G1, class G2, class V>
void PairBeaver<T, G1, G2, V>::init_pair()
{
    assert(this->prep);
    assert(this->MCec);
    assert(this->MCscalar);
    assert(this->MCg1);
    assert(this->MCg2);
    sharesGt.clear();
    sharesG1.clear();
    sharesG2.clear();
    sharesScalar.clear();
    openedEc.clear();
    openedG1.clear();
    openedG2.clear();
    openedScalar.clear();
    triples.clear();
}


template<class T, class G1, class G2, class V>
void PairBeaver<T, G1, G2, V>::prepare_mul(const T& x, const T& y, int n)
{ 
    (void) x;
    (void) y;
    (void) n;
    throw not_implemented(); 
}


template<class T, class G1, class G2, class V>
void PairBeaver<T, G1, G2, V>::prepare_scalar_mul(const V& x, const T& Y, int n)
{
    (void) n;
    triples.push_back({{}});
    auto& triple = triples.back();
    triple = prep->get_triple(n);
    sharesScalar.push_back(x - triple[0]);
    sharesGt.push_back(Y - triple[1]);
}


template<class T, class G1, class G2, class V>
void PairBeaver<T, G1, G2, V>::prepare_pair(const G1& X, const G2& Y, int n)
{
    (void) n;
    triples.push_back({{}});
    auto& triple = triples.back();
    triple = prep->get_triple(n);
    sharesScalar.push_back(x - triple[0]);
    sharesG1.push_back(X - triple[0]);
    sharesG2.push_back(Y - triple[1]);
}

// [a]<G>
template<class T, class G1, class G2, class V>
void PairBeaver<T, G1, G2, V>::ecscalarmulshare(typename T::open_type::Scalar multiplier, T pointshare, T& result){
    result.set_share(pointshare.get_share() * multiplier);
    result.set_mac(pointshare.get_mac() * multiplier);
}

// [<a>]G
template<class T, class G1, class G2, class V>
void PairBeaver<T, G1, G2, V>::ecscalarmulshare(V multiplierShare, typename T::open_type point, T& result){
    result.set_share(point * multiplierShare.get_share());
    result.set_mac(point * multiplierShare.get_mac());
}

template<class T, class G1, class G2, class V>
void PairBeaver<T, G1, G2, V>::exchange()
{
    MCscalar->POpen(openedScalar, sharesScalar, P);
    MCg1->POpen(openedG1, sharesG1, P);
    MCg2->POpen(openedG2, sharesG2, P);
    itG1 = openedG1.begin();
    itG2 = openedG2.begin();
    itScalar = openedScalar.begin();
    triple = triples.begin();
}

template<class T, class G1, class G2, class V>
T PairBeaver<T, G1, G2, V>::finalize_mul(int n)
{
    (void) n;
    typename V::open_type maskedScalar; // epsilon
    typename T::open_type maskedEc; // D

    V& a = (*triple)[0];
    T C = (*triple)[2];
    T B = (*triple)[1];
    T tmpec = {};

    maskedScalar = *itScalar;
    maskedEc = *itEc;

    ecscalarmulshare(maskedScalar, B, tmpec);
    C += tmpec;
    ecscalarmulshare(a, maskedEc, tmpec);
    C += tmpec;
    C += T::constant(maskedEc * maskedScalar, P.my_num(), MCec->get_alphai());
    triple++;
    itScalar++;
    itEc++;
    return C;
}

template<class T, class G1, class G2, class V>
T PairBeaver<T, G1, G2, V>::finalize_pair(int n)
{
    (void) n;
    typename V::open_type maskedScalar; // epsilon
    typename G1::open_type maskedG1; // Epsilon
    typename G2::open_type maskedG2; // Delta

    V& a = (*triple)[0];
    G1 B = (*triple)[1];
    G2 C = (*triple)[2];
    T tmpec = {};

    maskedScalar = *itScalar;
    maskedG1 = *itG1;
    maskedG2 = *itG2;

    // pair(C, g2) pair(maskedG1, B) pair(A, maskedG2), pair(maskedG1, maskedG2)
    ecscalarmulshare(maskedScalar, B, tmpec);
    C += tmpec;
    ecscalarmulshare(a, maskedEc, tmpec);
    C += tmpec;
    C += T::constant(maskedEc * maskedScalar, P.my_num(), MCec->get_alphai());
    triple++;
    itScalar++;
    itEc++;
    return C;
}



// PARALLEL FINALIZE MUL
template<class T, class G1, class G2, class V>
void PairBeaver<T, G1, G2, V>::finalize_mul(int count, thread_pool &pool, vector<T>& resvec)
{
    resvec.resize(count);
    auto mynum_ = P.my_num();
    for (int i = 0; i < count; i++)
    {
        typename V::open_type maskedScalar; // epsilon
        typename T::open_type maskedEc; // D

        V& a = (*triple)[0];
        T C = (*triple)[2];
        T B = (*triple)[1];
        maskedScalar = *itScalar;
        maskedEc = *itEc;
        auto alphai = MCec->get_alphai();

        pool.push_task([&resvec, i, maskedScalar, B, C, a, maskedEc, mynum_, alphai]{
            T tmpres = C;
            T tmpec = {};
            ecscalarmulshare(maskedScalar, B, tmpec);
            tmpres += tmpec;
            ecscalarmulshare(a, maskedEc, tmpec);
            tmpres += tmpec;
            tmpres += T::constant(maskedEc * maskedScalar, mynum_, alphai);
            resvec[i] = tmpres;
        });

        triple++;
        itScalar++;
        itEc++;
    }

    pool.wait_for_tasks();
}

template<class T, class G1, class G2, class V>
void PairBeaver<T, G1, G2, V>::check()
{
    assert(MCec);
    assert(MCscalar);
    MCec->Check(P);
    MCscalar->Check(P);
}


template<class T, class G1, class G2, class V>
T PairBeaver<T, G1, G2, V>::pair_g1share_p(G1 g1shareip){
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


template<class T, class G1, class G2, class V>
T PairBeaver<T, G1, G2, V>::pair_g1_g2share(G1::cle g1shareip){
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









#endif
