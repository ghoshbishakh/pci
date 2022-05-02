/*
 * blsElement.cpp
 *
 */

#include "blsElement.h"

#include "Math/gfp.hpp"

EC_GROUP* GtElement::curve;

void GtElement::init()
{
    curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    // bn_null(gtcurve);
    assert(curve != 0);
    auto modulus = EC_GROUP_get0_order(curve);
    Scalar::init_field(BN_bn2dec(modulus), false);
}

GtElement::GtElement()
{
    point = EC_POINT_new(curve);
    assert(point != 0);
    assert(EC_POINT_set_to_infinity(curve, point) != 0);
}

GtElement::GtElement(const Scalar& other) :
        GtElement()
{
    BIGNUM* exp = BN_new();
    BN_dec2bn(&exp, bigint(other).get_str().c_str());
    assert(EC_POINTs_mul(curve, point, exp, 0, 0, 0, 0) != 0);
    BN_free(exp);
}

GtElement::GtElement(word other) :
        GtElement()
{
    BIGNUM* exp = BN_new();
    BN_dec2bn(&exp, to_string(other).c_str());
    assert(EC_POINTs_mul(curve, point, exp, 0, 0, 0, 0) != 0);
    BN_free(exp);
}

GtElement& GtElement::operator =(const GtElement& other)
{
    assert(EC_POINT_copy(point, other.point) != 0);
    return *this;
}

void GtElement::check()
{
    assert(EC_POINT_is_on_curve(curve, point, 0) == 1);
}

GtElement::Scalar GtElement::x() const
{
    BIGNUM* x = BN_new();
    assert(EC_POINT_get_affine_coordinates_GFp(curve, point, x, 0, 0) != 0);
    char* xx = BN_bn2dec(x);
    Scalar res((bigint(xx)));
    OPENSSL_free(xx);
    BN_free(x);
    return res;
}

GtElement GtElement::operator +(const GtElement& other) const
{
    GtElement res;
    assert(EC_POINT_add(curve, res.point, point, other.point, 0) != 0);
    return res;
}

GtElement GtElement::operator -(const GtElement& other) const
{
    GtElement tmp = other;
    assert(EC_POINT_invert(curve, tmp.point, 0) != 0);
    return *this + tmp;
}

GtElement GtElement::operator *(const Scalar& other) const
{
    GtElement res;
    BIGNUM* exp = BN_new();
    BN_dec2bn(&exp, bigint(other).get_str().c_str());
    assert(EC_POINT_mul(curve, res.point, 0, point, exp, 0) != 0);
    BN_free(exp);
    return res;
}

bool GtElement::operator ==(const GtElement& other) const
{
    int cmp = EC_POINT_cmp(curve, point, other.point, 0);
    assert(cmp == 0 or cmp == 1);
    return not cmp;
}

void GtElement::pack(octetStream& os) const
{
    octet* buffer;
    size_t length = EC_POINT_point2buf(curve, point,
            POINT_CONVERSION_COMPRESSED, &buffer, 0);
    assert(length != 0);
    os.store_int(length, 8);
    os.append(buffer, length);
}

void GtElement::unpack(octetStream& os)
{
    size_t length = os.get_int(8);
    assert(
            EC_POINT_oct2point(curve, point, os.consume(length), length, 0)
                    != 0);
}

ostream& operator <<(ostream& s, const GtElement& x)
{
    char* hex = EC_POINT_point2hex(x.curve, x.point,
            POINT_CONVERSION_COMPRESSED, 0);
    s << hex;
    OPENSSL_free(hex);
    return s;
}

GtElement::GtElement(const GtElement& other) :
        GtElement()
{
    *this = other;
}

GtElement operator*(const GtElement::Scalar& x, const GtElement& y)
{
    return y * x;
}

GtElement& GtElement::operator +=(const GtElement& other)
{
    *this = *this + other;
    return *this;
}

GtElement& GtElement::operator /=(const Scalar& other)
{
    *this = *this * other.invert();
    return *this;
}

bool GtElement::operator !=(const GtElement& other) const
{
    return not (*this == other);
}

octetStream GtElement::hash(size_t n_bytes) const
{
    octetStream os;
    pack(os);
    auto res = os.hash();
    assert(n_bytes >= res.get_length());
    res.resize_precise(n_bytes);
    return res;
}

void GtElement::randomize(PRNG& G, int n)
{
    (void) n;
    GtElement::Scalar newscalar;
    newscalar.randomize(G, n);
    point = GtElement(newscalar).point;
}

void GtElement::input(istream& s,bool human)
{ 
    GtElement::Scalar newscalar;
    newscalar.input(s,human); 
    point = GtElement(newscalar).point;
}
