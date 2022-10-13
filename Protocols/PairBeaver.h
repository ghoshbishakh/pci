/*
 * PairBeaver.h
 *
 */

#ifndef PROTOCOLS_PAIRBEAVER_H_
#define PROTOCOLS_PAIRBEAVER_H_

#include <vector>
#include <array>
using namespace std;

#include "Replicated.h"
#include "Processor/Data_Files.h"
#include "bls/blsElement.h"
#include "Protocols/Share.h"


/**
 * Beaver pairing
 */
// T = Share<P256>, V = Share<G1Element::Scalar>
class PairBeaver : public ProtocolBase<Share<GtElement>>
{
protected:
    vector<Share<G1Element>> sharesG1;
    vector<Share<G2Element>> sharesG2;

    vector<typename Share<G1Element>::open_type> openedG1;
    vector<typename Share<G2Element>::open_type> openedG2;

    vector<typename Share<G1Element::Scalar>::open_type> openedScalar;
    vector<array<Share<G1Element::Scalar>, 3>> triples;
    typename vector<typename Share<G1Element>::open_type>::iterator itG1;
    typename vector<typename Share<G1Element::Scalar>::open_type>::iterator itScalar;
    typename vector<array<Share<G1Element::Scalar>, 3>>::iterator ittriple;
    Preprocessing<Share<G1Element::Scalar>>* prep;
    typename Share<GtElement>::MAC_Check* MCgt;
    typename Share<G1Element::Scalar>::MAC_Check* MCscalar;

public:
    static const bool uses_triples = true;

    Player& P;

    PairBeaver(Player& P) : prep(0), MCec(0), MCscalar(0), P(P) {}

    typename Share<GtElement>::Protocol branch();

    void init(Preprocessing<V>& prep, typename Share<GtElement>::MAC_Check& MCec, typename V::MAC_Check& MCscalar);

    static void ecscalarmulshare(typename Share<GtElement>::open_type::Scalar multiplier, Share<GtElement> pointshare, Share<GtElement>& result);
    static void ecscalarmulshare(V multiplierShare, typename Share<GtElement>::open_type point, Share<GtElement>& result);

    void init_mul();
    void prepare_mul(const Share<GtElement>& x, const Share<GtElement>& y, int n = -1);
    void prepare_scalar_mul(const V& x, const Share<GtElement>& Y, int n = -1);
    void exchange();
    Share<GtElement> finalize_mul(int n = -1);

    void check();

    void start_exchange();
    void stop_exchange();

    int get_n_relevant_players() { return 1 + Share<GtElement>::threshold(P.num_players()); }
};
#endif /* PROTOCOLS_PAIRBEAVER_H_ */
