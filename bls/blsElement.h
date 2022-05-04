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




class G1Element : public ValueInterface
{
public:
    typedef gfp_<2, 4> Scalar;

private:
    g1_t g1point;

public:
    typedef void next;
    typedef void Square;

    static const true_type invertible;

    static int size() { return 0; }
    static int length() { return 256; }
    static string type_string() { return "G1"; }

    void print_point();

    G1Element();
    G1Element(const G1Element& other);
    G1Element(const Scalar& other);
    G1Element(word other);

    G1Element& operator=(const G1Element& other);

    // void check();

    // Scalar x() const;
    void randomize(PRNG& G, int n = -1);
    void input(istream& s, bool human);
    static string type_short() { return "g1"; }
    static DataFieldType field_type() { return DATA_INT; }

    G1Element operator+(const G1Element& other) const;
    G1Element operator-(const G1Element& other) const;
    G1Element operator*(const Scalar& other) const;

    G1Element& operator+=(const G1Element& other);
    // G1Element& operator/=(const Scalar& other);

    bool operator==(const G1Element& other) const;
    bool operator!=(const G1Element& other) const;

    void assign_zero() { *this = {}; }
    bool is_zero() { return *this == G1Element(); }
    void add(octetStream& os) { *this += os.get<G1Element>(); }

    void pack(octetStream& os) const;
    void unpack(octetStream& os);

    // octetStream hash(size_t n_bytes) const;

    friend ostream& operator<<(ostream& s, const G1Element& x);
    void output(ostream& s,bool human) const;

};

G1Element operator*(const G1Element::Scalar& x, const G1Element& y);

#endif /* BLS_BLSELEMENT_H_ */
