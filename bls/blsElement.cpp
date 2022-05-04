/*
 * blsElement.cpp
 *
 */

#include "blsElement.h"

#include "Math/gfp.hpp"

bool GtElement::relic_initialized = false;
gt_t GtElement::gtgenerator;

void GtElement::init_relic()
{
    if (!relic_initialized) {
       if (core_init() != RLC_OK) {
        core_clean();
        }
        assert(pc_param_set_any() == RLC_OK);
    }
}

void GtElement::init() {
    // set order of Fp to gt
    bn_t gt_order;
    bn_null(gt_order);
    bn_new(gt_order);
    gt_get_ord(gt_order);
    char * gt_order_str = (char *)malloc(100 * sizeof(char));
    bn_write_str(gt_order_str, 100, gt_order, 10);
    Scalar::init_field(gt_order_str, false);
    // get generator
    gt_get_gen(gtgenerator);
    free(gt_order_str);
    bn_free(gt_order);
}

GtElement::GtElement()
{
    gt_null(gtpoint);
    gt_new(gtpoint);
    gt_set_unity(gtpoint);
}

GtElement::GtElement(const Scalar& other) :
        GtElement()
{
    bn_t x;
    bn_null(x);
    bn_new(x);
    string scalar_str = bigint(other).get_str();
    int scalar_len = scalar_str.size();
    bn_read_str(x, scalar_str.c_str(), scalar_len, 10);
    gt_exp(gtpoint, gtgenerator, x);
    bn_free(x);
}

// GtElement::GtElement(word other) :
//         GtElement()
// {
//     BIGNUM* exp = BN_new();
//     BN_dec2bn(&exp, to_string(other).c_str());
//     assert(EC_POINTs_mul(curve, point, exp, 0, 0, 0, 0) != 0);
//     BN_free(exp);
// }

// GtElement& GtElement::operator =(const GtElement& other)
// {
//     assert(EC_POINT_copy(point, other.point) != 0);
//     return *this;
// }

// void GtElement::check()
// {
//     assert(EC_POINT_is_on_curve(curve, point, 0) == 1);
// }

// GtElement::Scalar GtElement::x() const
// {
//     BIGNUM* x = BN_new();
//     assert(EC_POINT_get_affine_coordinates_GFp(curve, point, x, 0, 0) != 0);
//     char* xx = BN_bn2dec(x);
//     Scalar res((bigint(xx)));
//     OPENSSL_free(xx);
//     BN_free(x);
//     return res;
// }

// GtElement GtElement::operator +(const GtElement& other) const
// {
//     GtElement res;
//     assert(EC_POINT_add(curve, res.point, point, other.point, 0) != 0);
//     return res;
// }

// GtElement GtElement::operator -(const GtElement& other) const
// {
//     GtElement tmp = other;
//     assert(EC_POINT_invert(curve, tmp.point, 0) != 0);
//     return *this + tmp;
// }

// GtElement GtElement::operator *(const Scalar& other) const
// {
//     GtElement res;
//     BIGNUM* exp = BN_new();
//     BN_dec2bn(&exp, bigint(other).get_str().c_str());
//     assert(EC_POINT_mul(curve, res.point, 0, point, exp, 0) != 0);
//     BN_free(exp);
//     return res;
// }

// bool GtElement::operator ==(const GtElement& other) const
// {
//     int cmp = EC_POINT_cmp(curve, point, other.point, 0);
//     assert(cmp == 0 or cmp == 1);
//     return not cmp;
// }

// void GtElement::pack(octetStream& os) const
// {
//     octet* buffer;
//     size_t length = EC_POINT_point2buf(curve, point,
//             POINT_CONVERSION_COMPRESSED, &buffer, 0);
//     assert(length != 0);
//     os.store_int(length, 8);
//     os.append(buffer, length);
// }

// void GtElement::unpack(octetStream& os)
// {
//     size_t length = os.get_int(8);
//     assert(
//             EC_POINT_oct2point(curve, point, os.consume(length), length, 0)
//                     != 0);
// }

// ostream& operator <<(ostream& s, const GtElement& x)
// {
//     int size = gt_size_bin(x.gtpoint, 0);
//     uint8_t * gtoutstr = (uint8_t *)malloc(100 * sizeof(uint8_t));
//     gt_write_bin(gtoutstr, 100, x.gtpoint, 0);
//     s << gtoutstr;
//     gt_free(tmp);
//     free(gtoutstr);
//     return s;
// }

// GtElement::GtElement(const GtElement& other) :
//         GtElement()
// {
//     *this = other;
// }

// GtElement operator*(const GtElement::Scalar& x, const GtElement& y)
// {
//     return y * x;
// }

// GtElement& GtElement::operator +=(const GtElement& other)
// {
//     *this = *this + other;
//     return *this;
// }

// GtElement& GtElement::operator /=(const Scalar& other)
// {
//     *this = *this * other.invert();
//     return *this;
// }

// bool GtElement::operator !=(const GtElement& other) const
// {
//     return not (*this == other);
// }

// octetStream GtElement::hash(size_t n_bytes) const
// {
//     octetStream os;
//     pack(os);
//     auto res = os.hash();
//     assert(n_bytes >= res.get_length());
//     res.resize_precise(n_bytes);
//     return res;
// }

// void GtElement::randomize(PRNG& G, int n)
// {
//     (void) n;
//     GtElement::Scalar newscalar;
//     newscalar.randomize(G, n);
//     point = GtElement(newscalar).point;
// }

// void GtElement::input(istream& s,bool human)
// { 
//     GtElement::Scalar newscalar;
//     newscalar.input(s,human); 
//     point = GtElement(newscalar).point;
// }
