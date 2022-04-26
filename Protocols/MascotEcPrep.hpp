/*
 * MascotEcPrep.cpp
 *
 */

#ifndef PROTOCOLS_MASCOTECPREP_HPP_
#define PROTOCOLS_MASCOTECPREP_HPP_

#include "MascotEcPrep.h"



template<class T, class V>
MascotEcPrep<T, V>::MascotEcPrep(DataPositions& usage, MascotFieldPrep<V>& scalar_preprocessing):
Preprocessing<T>(usage),
scalar_preprocessing(scalar_preprocessing)
{
}

template<class T, class V>
MascotEcPrep<T, V>::MascotEcPrep(DataPositions& usage):
Preprocessing<T>(usage),
scalar_preprocessing(0, usage)
{
}



template<class T, class V>
void MascotEcPrep<T, V>::get_input_no_count(T& a, typename T::open_type& x, int i){
    V scalar_share;
    typename V::open_type scalar_value;
    scalar_preprocessing.get_input_no_count(scalar_share, scalar_value, i);
    a = scalar_share;
    x = scalar_value;
}




#endif