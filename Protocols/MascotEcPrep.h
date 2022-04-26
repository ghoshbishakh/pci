/*
 * MascotEcPrep.h
 *
 */

#ifndef PROTOCOLS_MASCOTECPREP_H_
#define PROTOCOLS_MASCOTECPREP_H_

#include "ReplicatedPrep.h"
#include "OT/MascotParams.h"
#include "Protocols/Share.h"
#include "Protocols/MascotPrep.h"
#include "Protocols/ReplicatedPrep.h"


// T is Share<P256Element>, V is Share<gfp>
template<class T, class V>
class MascotEcPrep :public Preprocessing<T>
{

MascotFieldPrep<V>& scalar_preprocessing;

public:
    MascotEcPrep<T, V>(DataPositions& usage);
    MascotEcPrep<T, V>(DataPositions& usage, MascotFieldPrep<V>& scalar_preprocessing);


    void get_input_no_count(T& a, typename T::open_type& x, int i);
};


#endif /* PROTOCOLS_MASCOTECPREP_H_ */