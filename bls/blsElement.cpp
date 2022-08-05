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

void GtElement::print_point()
{
    gt_print(gtpoint);
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
    gt_new(gtgenerator);
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

GtElement::~GtElement()
{
    gt_free(gtpoint);
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


GtElement::GtElement(gt_t other, bool distinguisher) :
        GtElement()
{
    (void) distinguisher;
    gt_copy(gtpoint, other);
}


GtElement::GtElement(word other) :
        GtElement()
{
    bn_t x;
    bn_null(x);
    bn_new(x);
    string scalar_str = to_string(other);
    int scalar_len = scalar_str.size();
    bn_read_str(x, scalar_str.c_str(), scalar_len, 10);
    gt_exp(gtpoint, gtgenerator, x);
    bn_free(x);
}

GtElement& GtElement::operator =(const GtElement& other)
{
    gt_t tmp;
    gt_null(tmp);
    gt_new(tmp);
    memcpy(tmp, other.gtpoint, sizeof(other.gtpoint));
    gt_copy(gtpoint, tmp);
    gt_free(tmp);
    return *this;
}


GtElement GtElement::operator +(const GtElement& other) const
{
    // define + as multiplication
    GtElement res;

    gt_t tmp1, tmp2;
    gt_null(tmp1); gt_null(tmp2);
    gt_new(tmp1); gt_new(tmp2);
    memcpy(tmp1, other.gtpoint, sizeof(other.gtpoint));
    memcpy(tmp2, gtpoint, sizeof(gtpoint));
    gt_mul(res.gtpoint, tmp2, tmp1);
        
    gt_free(tmp1); gt_free(tmp2);

    return res;
}

GtElement GtElement::operator -(const GtElement& other) const
{
    GtElement res;

    gt_t tmp1, tmp2;
    gt_null(tmp1); gt_null(tmp2);
    gt_new(tmp1); gt_new(tmp2);
    memcpy(tmp1, other.gtpoint, sizeof(other.gtpoint));
    gt_inv(tmp1, tmp1);
    memcpy(tmp2, gtpoint, sizeof(gtpoint));
    gt_mul(res.gtpoint, tmp2, tmp1);
    gt_free(tmp1); gt_free(tmp2);

    return res;
}

GtElement GtElement::operator *(const Scalar& other) const
{
    GtElement res;
    gt_t tmp;
    gt_null(tmp);
    gt_new(tmp);
    memcpy(tmp, gtpoint, sizeof(gtpoint));
    bn_t x;
    bn_null(x);
    bn_new(x);
    string scalar_str = bigint(other).get_str();
    int scalar_len = scalar_str.size();
    bn_read_str(x, scalar_str.c_str(), scalar_len, 10);
    gt_exp(res.gtpoint, tmp, x);
    bn_free(x);
    gt_free(tmp);

    return res;
}

bool GtElement::operator ==(const GtElement& other) const
{
    gt_t tmp1, tmp2;
    gt_null(tmp1); gt_null(tmp2);
    gt_new(tmp1); gt_new(tmp2);
    memcpy(tmp1, gtpoint, sizeof(gtpoint));
    memcpy(tmp2, other.gtpoint, sizeof(other.gtpoint));
    
    if(gt_cmp(tmp1, tmp2) == RLC_EQ){
        gt_free(tmp1); gt_free(tmp2);
        return 1;
    }
    
    gt_free(tmp1); gt_free(tmp2);
    return 0;
}

void GtElement::pack(octetStream& os) const
{
    gt_t tmp;
    gt_null(tmp);
    gt_new(tmp);
    memcpy(tmp, gtpoint, sizeof(gtpoint));
    int binsize = gt_size_bin(tmp, 1);
    uint8_t * gtoutstr = (uint8_t *)malloc(binsize * sizeof(uint8_t));
    gt_write_bin(gtoutstr, binsize, tmp, 1);
    os.store_int(binsize, 8);
    os.append(gtoutstr, binsize);
    gt_free(tmp);
    free(gtoutstr);
}

void GtElement::unpack(octetStream& os)
{
    size_t binsize = os.get_int(8);
    gt_read_bin(gtpoint, os.consume(binsize), binsize);
}

ostream& operator <<(ostream& s, const GtElement& x)
{
    gt_t tmp;
    gt_null(tmp);
    gt_new(tmp);
    memcpy(tmp, x.gtpoint, sizeof(x.gtpoint));
    int binsize = gt_size_bin(tmp, 1);
    uint8_t * gtoutstr = (uint8_t *)malloc(binsize * sizeof(uint8_t));
    gt_write_bin(gtoutstr, binsize, tmp, 1);
    for(int i=0; i<binsize; ++i){
        s << hex << (int)gtoutstr[i] << dec;
    }
    gt_free(tmp);
    free(gtoutstr);
    return s;
}

void GtElement::output(ostream& s,bool human) const
{
    (void) human;
    gt_t tmp;
    gt_null(tmp);
    gt_new(tmp);
    memcpy(tmp, gtpoint, sizeof(gtpoint));
    int binsize = gt_size_bin(tmp, 1);
    gt_free(tmp);
    uint8_t * gtoutstr = (uint8_t *)malloc(binsize * sizeof(uint8_t));
    gt_write_bin(gtoutstr, binsize, tmp, 1);
    for(int i=0; i<binsize; ++i){
        s << hex << (int)gtoutstr[i] << dec;
    }
    gt_free(tmp);
    free(gtoutstr);
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

bool GtElement::operator !=(const GtElement& other) const
{
    return not (*this == other);
}


void GtElement::randomize(PRNG& G, int n)
{
    (void) n;
    GtElement::Scalar newscalar;
    newscalar.randomize(G, n);
    gt_copy(gtpoint, GtElement(newscalar).gtpoint);
}

void GtElement::input(istream& s,bool human)
{ 
    (void) s;
    (void) human;
    throw runtime_error("gt input not implemented");
}








// ==============================================








void G1Element::print_point()
{
    g1_print(g1point);
}

G1Element::G1Element()
{
    g1_null(g1point);
    g1_new(g1point);
    g1_set_infty(g1point);
}

G1Element::~G1Element()
{
    g1_free(g1point);
}

G1Element::G1Element(const Scalar& other) :
        G1Element()
{
    bn_t x;
    bn_null(x);
    bn_new(x);
    string scalar_str = bigint(other).get_str();
    int scalar_len = scalar_str.size();
    bn_read_str(x, scalar_str.c_str(), scalar_len, 10);
    g1_mul_gen(g1point, x);
    bn_free(x);
}

G1Element::G1Element(g1_t other, bool distinguisher) :
        G1Element()
{
    (void) distinguisher;
    g1_copy(g1point, other);
}

G1Element::G1Element(word other) :
        G1Element()
{
    bn_t x;
    bn_null(x);
    bn_new(x);
    string scalar_str = to_string(other);
    int scalar_len = scalar_str.size();
    bn_read_str(x, scalar_str.c_str(), scalar_len, 10);
    g1_mul_gen(g1point, x);
    bn_free(x);
}

G1Element& G1Element::operator =(const G1Element& other)
{
    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);
    memcpy(tmp, other.g1point, sizeof(other.g1point));
    g1_copy(g1point, tmp);
    g1_free(tmp);
    return *this;
}

// void G1Element::check()
// {
//     assert(EC_POINT_is_on_curve(curve, point, 0) == 1);
// }

// G1Element::Scalar G1Element::x() const
// {
//     BIGNUM* x = BN_new();
//     assert(EC_POINT_get_affine_coordinates_GFp(curve, point, x, 0, 0) != 0);
//     char* xx = BN_bn2dec(x);
//     Scalar res((bigint(xx)));
//     OPENSSL_free(xx);
//     BN_free(x);
//     return res;
// }

G1Element G1Element::operator +(const G1Element& other) const
{
    G1Element res;

    g1_t tmp1, tmp2;
    g1_null(tmp1); g1_null(tmp2);
    g1_new(tmp1); g1_new(tmp2);
    memcpy(tmp1, other.g1point, sizeof(other.g1point));
    memcpy(tmp2, g1point, sizeof(g1point));
    g1_add(res.g1point, tmp2, tmp1);
        
    g1_free(tmp1); g1_free(tmp2);

    return res;
}

G1Element G1Element::operator -(const G1Element& other) const
{
    G1Element res;

    g1_t tmp1, tmp2;
    g1_null(tmp1); g1_null(tmp2);
    g1_new(tmp1); g1_new(tmp2);
    memcpy(tmp1, other.g1point, sizeof(other.g1point));
    memcpy(tmp2, g1point, sizeof(g1point));
    g1_sub(res.g1point, tmp2, tmp1);
        
    g1_free(tmp1); g1_free(tmp2);

    return res;
}

G1Element G1Element::operator *(const Scalar& other) const
{
    G1Element res;
    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);
    memcpy(tmp, g1point, sizeof(g1point));
    bn_t x;
    bn_null(x);
    bn_new(x);
    string scalar_str = bigint(other).get_str();
    int scalar_len = scalar_str.size();
    bn_read_str(x, scalar_str.c_str(), scalar_len, 10);
    g1_mul(res.g1point, tmp, x);
    bn_free(x);
    g1_free(tmp);

    return res;
}

bool G1Element::operator ==(const G1Element& other) const
{
    g1_t tmp1, tmp2;
    g1_null(tmp1); g1_null(tmp2);
    g1_new(tmp1); g1_new(tmp2);
    memcpy(tmp1, g1point, sizeof(g1point));
    memcpy(tmp2, other.g1point, sizeof(other.g1point));
    
    if(g1_cmp(tmp1, tmp2) == RLC_EQ){
        g1_free(tmp1); g1_free(tmp2);
        return 1;
    }
    
    g1_free(tmp1); g1_free(tmp2);
    return 0;
}

void G1Element::pack(octetStream& os) const
{
    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);
    memcpy(tmp, g1point, sizeof(g1point));
    int binsize = g1_size_bin(tmp, 1);
    uint8_t * gtoutstr = (uint8_t *)malloc(binsize * sizeof(uint8_t));
    g1_write_bin(gtoutstr, binsize, tmp, 1);
    os.store_int(binsize, 8);
    os.append(gtoutstr, binsize);
    g1_free(tmp);
    free(gtoutstr);
}

void G1Element::unpack(octetStream& os)
{
    size_t binsize = os.get_int(8);
    g1_read_bin(g1point, os.consume(binsize), binsize);
}

ostream& operator <<(ostream& s, const G1Element& x)
{
    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);
    memcpy(tmp, x.g1point, sizeof(x.g1point));
    int binsize = g1_size_bin(tmp, 1);
    uint8_t * gtoutstr = (uint8_t *)malloc(binsize * sizeof(uint8_t));
    g1_write_bin(gtoutstr, binsize, tmp, 1);
    for(int i=0; i<binsize; ++i){
        s << hex << (int)gtoutstr[i] << dec;
    }
    g1_free(tmp);
    free(gtoutstr);
    return s;
}

void G1Element::output(ostream& s,bool human) const
{
    (void) human;
    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);
    memcpy(tmp, g1point, sizeof(g1point));
    int binsize = g1_size_bin(tmp, 1);
    g1_free(tmp);
    uint8_t * gtoutstr = (uint8_t *)malloc(binsize * sizeof(uint8_t));
    g1_write_bin(gtoutstr, binsize, tmp, 1);
    for(int i=0; i<binsize; ++i){
        s << hex << (int)gtoutstr[i] << dec;
    }
    g1_free(tmp);
    free(gtoutstr);
}


G1Element::G1Element(const G1Element& other) :
        G1Element()
{
    *this = other;
}

G1Element operator*(const G1Element::Scalar& x, const G1Element& y)
{
    return y * x;
}

G1Element& G1Element::operator +=(const G1Element& other)
{
    *this = *this + other;
    return *this;
}

// G1Element& G1Element::operator /=(const Scalar& other)
// {
//     *this = *this * other.invert();
//     return *this;
// }

bool G1Element::operator !=(const G1Element& other) const
{
    return not (*this == other);
}

// octetStream G1Element::hash(size_t n_bytes) const
// {
//     octetStream os;
//     pack(os);
//     auto res = os.hash();
//     assert(n_bytes >= res.get_length());
//     res.resize_precise(n_bytes);
//     return res;
// }

void G1Element::randomize(PRNG& G, int n)
{
    (void) n;
    G1Element::Scalar newscalar;
    newscalar.randomize(G, n);
    g1_copy(g1point, G1Element(newscalar).g1point);
}

void G1Element::input(istream& s,bool human)
{ 
    (void) s;
    (void) human;
    throw runtime_error("gt input not implemented");
}

void G1Element::copypoint(g1_t dest){
    g1_copy(dest, g1point);
}

void G1Element::setpoint(g1_t src){
    g1_copy(g1point, src);
}


G1Element G1Element::sign(uint8_t *msg, int len, G1Element::Scalar sk){
    G1Element res;
    bn_t x;
    bn_null(x);
    bn_new(x);
    g1_t y;
    g1_null(y);
    g1_new(y);

    string scalar_str = bigint(sk).get_str();
    int scalar_len = scalar_str.size();
    bn_read_str(x, scalar_str.c_str(), scalar_len, 10);

    cp_bls_sig(y, msg, len, x);
    res.setpoint(y);
    
    bn_free(x);
    g1_free(y);

    return res;
};


bool G1Element::ver(G1Element sig, uint8_t *msg, int len, G2Element pk){
    g2_t y;
    g2_null(y);
    g2_new(y);
    pk.copypoint(y);

    g1_t s;
    g1_null(s);
    g1_new(s);
    sig.copypoint(s);

    if(cp_bls_ver(s, msg, len, y)){
        g2_free(y);
        g1_free(s);

        return true;
    }
    g2_free(y);
    g1_free(s);

    return false;
};


// ==============================================








void G2Element::print_point()
{
    g2_print(g2point);
}

G2Element::G2Element()
{
    g2_null(g2point);
    g2_new(g2point);
    g2_set_infty(g2point);
}

G2Element::~G2Element()
{
    g2_free(g2point);
}


G2Element::G2Element(const Scalar& other) :
        G2Element()
{
    bn_t x;
    bn_null(x);
    bn_new(x);
    string scalar_str = bigint(other).get_str();
    int scalar_len = scalar_str.size();
    bn_read_str(x, scalar_str.c_str(), scalar_len, 10);
    g2_mul_gen(g2point, x);
    bn_free(x);
}


G2Element::G2Element(word other) :
        G2Element()
{
    bn_t x;
    bn_null(x);
    bn_new(x);
    string scalar_str = to_string(other);
    int scalar_len = scalar_str.size();
    bn_read_str(x, scalar_str.c_str(), scalar_len, 10);
    g2_mul_gen(g2point, x);
    bn_free(x);
}

G2Element& G2Element::operator =(const G2Element& other)
{
    g2_t tmp;
    g2_null(tmp);
    g2_new(tmp);
    memcpy(tmp, other.g2point, sizeof(other.g2point));
    g2_copy(g2point, tmp);
    g2_free(tmp);
    return *this;
}

// void G2Element::check()
// {
//     assert(EC_POINT_is_on_curve(curve, point, 0) == 1);
// }

// G2Element::Scalar G2Element::x() const
// {
//     BIGNUM* x = BN_new();
//     assert(EC_POINT_get_affine_coordinates_GFp(curve, point, x, 0, 0) != 0);
//     char* xx = BN_bn2dec(x);
//     Scalar res((bigint(xx)));
//     OPENSSL_free(xx);
//     BN_free(x);
//     return res;
// }

G2Element G2Element::operator +(const G2Element& other) const
{
    G2Element res;

    g2_t tmp1, tmp2;
    g2_null(tmp1); g2_null(tmp2);
    g2_new(tmp1); g2_new(tmp2);
    memcpy(tmp1, other.g2point, sizeof(other.g2point));
    memcpy(tmp2, g2point, sizeof(g2point));
    g2_add(res.g2point, tmp2, tmp1);
        
    g2_free(tmp1); g2_free(tmp2);

    return res;
}

G2Element G2Element::operator -(const G2Element& other) const
{
    G2Element res;

    g2_t tmp1, tmp2;
    g2_null(tmp1); g2_null(tmp2);
    g2_new(tmp1); g2_new(tmp2);
    memcpy(tmp1, other.g2point, sizeof(other.g2point));
    memcpy(tmp2, g2point, sizeof(g2point));
    g2_sub(res.g2point, tmp2, tmp1);
        
    g2_free(tmp1); g2_free(tmp2);

    return res;
}

G2Element G2Element::operator *(const Scalar& other) const
{
    G2Element res;
    g2_t tmp;
    g2_null(tmp);
    g2_new(tmp);
    memcpy(tmp, g2point, sizeof(g2point));
    bn_t x;
    bn_null(x);
    bn_new(x);
    string scalar_str = bigint(other).get_str();
    int scalar_len = scalar_str.size();
    bn_read_str(x, scalar_str.c_str(), scalar_len, 10);
    g2_mul(res.g2point, tmp, x);
    bn_free(x);
    g2_free(tmp);

    return res;
}

bool G2Element::operator ==(const G2Element& other) const
{
    g2_t tmp1, tmp2;
    g2_null(tmp1); g2_null(tmp2);
    g2_new(tmp1); g2_new(tmp2);
    memcpy(tmp1, g2point, sizeof(g2point));
    memcpy(tmp2, other.g2point, sizeof(other.g2point));
    
    if(g2_cmp(tmp1, tmp2) == RLC_EQ){
        g2_free(tmp1); g2_free(tmp2);
        return 1;
    }
    
    g2_free(tmp1); g2_free(tmp2);
    return 0;
}

void G2Element::pack(octetStream& os) const
{
    g2_t tmp;
    g2_null(tmp);
    g2_new(tmp);
    memcpy(tmp, g2point, sizeof(g2point));
    int binsize = g2_size_bin(tmp, 1);
    uint8_t * gtoutstr = (uint8_t *)malloc(binsize * sizeof(uint8_t));
    g2_write_bin(gtoutstr, binsize, tmp, 1);
    os.store_int(binsize, 8);
    os.append(gtoutstr, binsize);
    g2_free(tmp);
    free(gtoutstr);
}

void G2Element::unpack(octetStream& os)
{
    size_t binsize = os.get_int(8);
    g2_read_bin(g2point, os.consume(binsize), binsize);
}

ostream& operator <<(ostream& s, const G2Element& x)
{
    g2_t tmp;
    g2_null(tmp);
    g2_new(tmp);
    memcpy(tmp, x.g2point, sizeof(x.g2point));
    int binsize = g2_size_bin(tmp, 1);
    uint8_t * gtoutstr = (uint8_t *)malloc(binsize * sizeof(uint8_t));
    g2_write_bin(gtoutstr, binsize, tmp, 1);
    for(int i=0; i<binsize; ++i){
        s << hex << (int)gtoutstr[i] << dec;
    }
    g2_free(tmp);
    free(gtoutstr);
    return s;
}

void G2Element::output(ostream& s,bool human) const
{
    (void) human;
    g2_t tmp;
    g2_null(tmp);
    g2_new(tmp);
    memcpy(tmp, g2point, sizeof(g2point));
    int binsize = g2_size_bin(tmp, 1);
    g2_free(tmp);
    uint8_t * gtoutstr = (uint8_t *)malloc(binsize * sizeof(uint8_t));
    g2_write_bin(gtoutstr, binsize, tmp, 1);
    for(int i=0; i<binsize; ++i){
        s << hex << (int)gtoutstr[i] << dec;
    }
    g2_free(tmp);
    free(gtoutstr);
}


G2Element::G2Element(const G2Element& other) :
        G2Element()
{
    *this = other;
}

G2Element operator*(const G2Element::Scalar& x, const G2Element& y)
{
    return y * x;
}

G2Element& G2Element::operator +=(const G2Element& other)
{
    *this = *this + other;
    return *this;
}

// G2Element& G2Element::operator /=(const Scalar& other)
// {
//     *this = *this * other.invert();
//     return *this;
// }

bool G2Element::operator !=(const G2Element& other) const
{
    return not (*this == other);
}

// octetStream G2Element::hash(size_t n_bytes) const
// {
//     octetStream os;
//     pack(os);
//     auto res = os.hash();
//     assert(n_bytes >= res.get_length());
//     res.resize_precise(n_bytes);
//     return res;
// }

void G2Element::randomize(PRNG& G, int n)
{
    (void) n;
    G2Element::Scalar newscalar;
    newscalar.randomize(G, n);
    g2_copy(g2point, G2Element(newscalar).g2point);
}

void G2Element::input(istream& s,bool human)
{ 
    (void) s;
    (void) human;
    throw runtime_error("gt input not implemented");
}

void G2Element::copypoint(g2_t dest){
    g2_copy(dest, g2point);
}


// ================================================



GtElement pair_g1_g2(G1Element g1ip, G2Element g2ip) {
    gt_t res;
    gt_null(res);
    gt_new(res);

    g2_t g2val;
    g2_null(g2val);
    g2_new(g2val);

    g1_t g1val;
    g1_null(g1val);
    g1_new(g1val);

    g1ip.copypoint(g1val);
    g2ip.copypoint(g2val);

    pc_map(res, g1val, g2val);
    GtElement pair_result(res, false);

    g2_free(g2val);
    g1_free(g1val);
    gt_free(res);

    return pair_result;
};


G1Element msg_to_g1(uint8_t *msg, int len){
    g1_t g1val;
    g1_null(g1val);
    g1_new(g1val);
    g1_map(g1val, msg, len);

    G1Element res(g1val, false);

    g1_free(g1val);
    return res;
}





