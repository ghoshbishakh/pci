/*
 * blsElement.h
 *
 */

#ifndef BLS_BLSELEMENT_H_
#define BLS_BLSELEMENT_H_

#include "Math/gfp.h"
extern "C" {
#include <relic/relic_core.h>
#include <relic/relic_bn.h>
#include <relic/relic_pc.h>
#include <relic/relic_cp.h>
}



class GtElement : public ValueInterface
{
public:
    typedef gfp_<2, 4> Scalar;

private:
    gt_t gtpoint;
    static bool relic_initialized;
    static gt_t gtgenerator;


public:
    typedef void next;
    typedef void Square;

    static const true_type invertible;

    static int size() { return 0; }
    static int length() { return 256; }
    static string type_string() { return "GT"; }

    static void init();
    static void init_relic();
    void print_point();

    GtElement();
    GtElement(const GtElement& other);
    GtElement(const Scalar& other);
    GtElement(word other);

    GtElement& operator=(const GtElement& other);

    // void check();

    // Scalar x() const;
    void randomize(PRNG& G, int n = -1);
    void input(istream& s, bool human);
    static string type_short() { return "gt"; }
    static DataFieldType field_type() { return DATA_INT; }

    GtElement operator+(const GtElement& other) const;
    GtElement operator-(const GtElement& other) const;
    GtElement operator*(const Scalar& other) const;

    GtElement& operator+=(const GtElement& other);
    // GtElement& operator/=(const Scalar& other);

    bool operator==(const GtElement& other) const;
    bool operator!=(const GtElement& other) const;

    void assign_zero() { *this = {}; }
    bool is_zero() { return *this == GtElement(); }
    void add(octetStream& os) { *this += os.get<GtElement>(); }

    void pack(octetStream& os) const;
    void unpack(octetStream& os);

    // octetStream hash(size_t n_bytes) const;

    friend ostream& operator<<(ostream& s, const GtElement& x);
    void output(ostream& s,bool human) const;

};

GtElement operator*(const GtElement::Scalar& x, const GtElement& y);

#endif /* BLS_BLSELEMENT_H_ */
