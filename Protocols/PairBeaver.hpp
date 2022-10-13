/*
 * PairBeaver.cpp
 *
 */

#ifndef PROTOCOLS_PAIRBEAVER_HPP_
#define PROTOCOLS_PAIRBEAVER_HPP_

#include "PairBeaver.h"

#include "Replicated.hpp"

#include <array>

template<class T, class V>
typename T::Protocol PairBeaver<T, V>::branch()
{
    typename T::Protocol res(P);
    res.prep = prep;
    res.MCec = MCec;
    res.MCscalar = MCscalar;
    res.init_mul();
    return res;
}

template<class T, class V>
void PairBeaver<T, V>::init(Preprocessing<V>& prep, typename T::MAC_Check& MCec, typename V::MAC_Check& MCscalar)
{
    this->prep = &prep;
    this->MCec = &MCec;
    this->MCscalar = &MCscalar;
}

template<class T, class V>
void PairBeaver<T, V>::init_mul()
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
void PairBeaver<T, V>::prepare_mul(const T& x, const T& y, int n)
{ 
    (void) x;
    (void) y;
    (void) n;
    throw not_implemented(); 
}


template<class T, class V>
void PairBeaver<T, V>::prepare_scalar_mul(const V& x, const T& Y, int n)
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
void PairBeaver<T, V>::ecscalarmulshare(typename T::open_type::Scalar multiplier, T pointshare, T& result){
    result.set_share(pointshare.get_share() * multiplier);
    result.set_mac(pointshare.get_mac() * multiplier);
}

// [<a>]G
template<class T, class V>
void PairBeaver<T, V>::ecscalarmulshare(V multiplierShare, typename T::open_type point, T& result){
    result.set_share(point * multiplierShare.get_share());
    result.set_mac(point * multiplierShare.get_mac());
}

template<class T, class V>
void PairBeaver<T, V>::exchange()
{
    MCec->POpen(openedEc, sharesEc, P);
    MCscalar->POpen(openedScalar, sharesScalar, P);
    itEc = openedEc.begin();
    itScalar = openedScalar.begin();
    triple = triples.begin();
}

template<class T, class V>
void PairBeaver<T, V>::start_exchange()
{
    MCec->POpen_Begin(openedEc, sharesEc, P);
    MCscalar->POpen_Begin(openedScalar, sharesScalar, P);
}

template<class T, class V>
void PairBeaver<T, V>::stop_exchange()
{
    MCec->POpen_End(openedEc, sharesEc, P);
    MCscalar->POpen_End(openedScalar, sharesScalar, P);
    itEc = openedEc.begin();
    itScalar = openedScalar.begin();
    triple = triples.begin();
}

template<class T, class V>
T PairBeaver<T, V>::finalize_mul(int n)
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

template<class T, class V>
void PairBeaver<T, V>::check()
{
    assert(MCec);
    assert(MCscalar);
    MCec->Check(P);
    MCscalar->Check(P);
}

#endif
