/*
  ecpfix.c

  Copyright:
          Copyright (c) 2002-2007 SFNT Finland Oy.
  All rights reserved.

  Elliptic curve fixed parameters.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshgenmp.h"
#include "sshcrypt.h"
#include "ecpfix.h"
#include "sshbuffer.h"
#include "sshgetput.h"

#ifdef SSHDIST_CRYPT_ECP
#ifdef SSHDIST_MATH_ECP
/* Fixed parameters. */

typedef struct
{
  const char *name;
  const char *q;
  const char *a;
  const char *b;
  const char *c;
  const char *px, *py;
  const char *n;
} SshECPFixedParams;

/* All fixed parameters should satisfy atleast:

   - generated randomly (field modulus, curve constants and the point)
   - near prime cardinality
   - point has large prime order

   There are also other criterias which could be applied, but these mentioned
   seem currently strong enough.
   */

#define SSH_ECP_FIXED_POINT_COMPRESS       FALSE
#define SSH_DEFAULT_EC_MODP_CURVE_NAME     "ssh-ec-modp-curve-155bit-1"

const SshECPFixedParams ssh_ecp_fixed_params[] =
{
  {
    /* 155 bits */

    "ssh-ec-modp-curve-155bit-1",

    /* q */
    "31407857097127860965216287356072559134859825543",
    /* a */
    "2731256435122317801261871679028549091389013906",
    /* b */
    "10714317566020843022911894761291265613594418240",
     /* #E(Fq) */
    "31407857097127860965216427618348169229298502938",
    /* P_x */
    "16392655484387136812157475999461840857228033620",
    /* P_y */
    "2799086322187201568878931628895797117411224036",
    /* #P */
    "402664834578562320066877277158309861914083371"
  },
  {
    /* 155 bits */
    "ssh-ec-modp-curve-155bit-2",

    /* q */
    "36297272659662506860980360407302074284133162871",
    /* a */
    "27124701431231299400484722496484295443330204918",
    /* b */
    "30301737350042067130127502794912132619158043000",
    /* #E(Fq) */
    "36297272659662506860980147341067393239091873883",
    /* P_x */
    "11711116373547979507936212029780235644179397805",
    /* P_y */
    "32762560063802500788917178597259173957396445450",
    /* #P */
    "33640575491381625732043477771053949671671"
  },
  {
    /* SECP 160 bit curve (r1) */
    "secp160r1",

    /* q */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
    /* a */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC",
    /* b */
    "0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45",
    /* #E(Fq)a */
    "1461501637330902918203687197606826779884643492439",
    /* P_x */
    "0x4A96B5688EF573284664698968C38BB913CBFC82",
    /* P_y */
    "0x23a628553168947d59dcc912042351377ac5fb32",
    /* #P */
    "0x0100000000000000000001F4C8F927AED3CA752257"
  },
  {
    /* 175 bits */
    "ssh-ec-modp-curve-175bit-1",

    /* q */
    "40950177705606685781046242922154881607956178336371883",
    /* a */
    "24746273018219762494198595506743299332378325756031886",
    /* b */
    "6503278719366954296567774236884439158775557920331547",
    /* #E(Fq) */
    "40950177705606685781046243158324028591251169648712266",
    /* P_x */
    "6408402137441767794969170236925842559451119808358974",
    /* P_y */
    "39032544798419387403330432854399185547513580950826190",
    /* #P */
    "2750918830149582546086674940099692905498533497831"
  },
  {
    /* 175 bits */
    "ssh-ec-modp-curve-175bit-2",

     /* q */
    "25133914800611099026082727697808480710160935689515477",
    /* a */
    "17146225641958545872320149903955451167573508624853931",
    /* b */
    "21261641208097867800497328477718361404177050434117193",
    /* #E(Fq) */
    "25133914800611099026082727581231133979322149086167579",
    /* P_x */
    "8738002582171225345779025855668373615175447647735275",
    /* P_y */
    "6530642698522393684297998663212006319191306125962008",
    /* #P */
    "474718057534367152656837489904956793301367209"
  },
  {
    /* 192 bits */
    "secp192r1",

    /* q */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
    /* a */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
    /* b */
    "0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
    /* #E(Fq) */
    "0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
    /* P_x */
    "0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
    /* P_y */
    "0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
    /* #P */
    "0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"
  },
  {
    /* 224 bits */
    "secp224r1",

    /* q */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
    /* a */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
    /* b */
    "0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
    /* #E(Fq) */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
    /* P_x */
    "0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
    /* P_y */
    "0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
    /* #P */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"
  },
  {
    /* 256 bits */
    "prime256v1",
    /* q =  2^(256)-2^(224)+2^(192)+2^(96)-1 */
    "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    /* a (= -3) */
    "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
    /* b */
    "0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
    /* #E(Fq) */
    "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    /* P_x */
    "0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
    /* P_y */
    "0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    /* #P */
    "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
  },
  {
    "secp384r1",
    /* q =  2^(384)-2^(128)-2^(96)+2^(32)-1 */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "EFFFFFFFF0000000000000000FFFFFFFF",
    /* a (= -3) */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "EFFFFFFFF0000000000000000FFFFFFFC",
    /* b */
    "0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
    "C656398D8A2ED19D2A85C8EDD3EC2AEF",
    /* #E(Fq) */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A"
    "0DB248B0A77AECEC196ACCC52973",
    /* P_x */
    "0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
    "5502F25DBF55296C3A545E3872760AB7",
    /* P_y */
    "0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
    "0A60B1CE1D7E819D7A431D7C90EA0E5F",
    /* #P */
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
    "581A0DB248B0A77AECEC196ACCC52973"
  },
  {
    "secp521r1",
    /* q =  2^(521)-1 */
    "0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    /* a (= -3) */
    "0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
    /* b */
    "0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
    "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50"
    "3F00",
    /* #E(Fq) */
    "0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "A51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    /* P_x */
    "0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D"
    "3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5"
    "BD66",
    /* P_y */
    "0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E"
    "662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD1"
    "6650",
    /* #P */
    "0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E9138"
    "6409"
  },

  { NULL },
};

char *ssh_ecp_param_get_predefined_groups(void)
{
  char *list;
  SshBufferStruct buffer;
  unsigned int i;

  list = NULL;
  ssh_buffer_init(&buffer);
  for (i = 0; ssh_ecp_fixed_params[i].name; i++)
    {
      if (ssh_buffer_len(&buffer) > 0)
        {
          if (ssh_buffer_append(&buffer, (const unsigned char *)",", 1)
              != SSH_BUFFER_OK)
            goto failure;
        }
      if (ssh_buffer_append(&buffer,
                            (const unsigned char *)
                            ssh_ecp_fixed_params[i].name,
                            strlen(ssh_ecp_fixed_params[i].name))
          != SSH_BUFFER_OK)
        goto failure;
    }

  if (ssh_buffer_append(&buffer, (const unsigned char *)"\0", 1)
      == SSH_BUFFER_OK)
    list = ssh_strdup(ssh_buffer_ptr(&buffer));

 failure:
  ssh_buffer_uninit(&buffer);
  return list;
}

Boolean ssh_ecp_set_param(const char *name, const char **outname,
                          SshECPCurve E, SshECPPoint P, SshMPInteger n,
                          Boolean *pc)
{
  int i;
  SshMPIntegerStruct a, b, c, q, x, y;
  Boolean rv = FALSE;

  /* Have some default name. */
  if (name == NULL)
    name = SSH_DEFAULT_EC_MODP_CURVE_NAME;

  for (i = 0; ssh_ecp_fixed_params[i].name; i++)
    {
      if (strcmp(ssh_ecp_fixed_params[i].name, name) == 0)
        break;
    }
  if (ssh_ecp_fixed_params[i].name == NULL)
    return FALSE;

  *pc = SSH_ECP_FIXED_POINT_COMPRESS;

  *outname = ssh_ecp_fixed_params[i].name;

  /* Read in the integers. */
  ssh_mprz_init(&a);
  ssh_mprz_init(&b);
  ssh_mprz_init(&c);
  ssh_mprz_init(&q);
  ssh_mprz_init(&x);
  ssh_mprz_init(&y);

  /* Initialize. */
  ssh_mprz_set_str(&q, ssh_ecp_fixed_params[i].q, 0);
  ssh_mprz_set_str(&a, ssh_ecp_fixed_params[i].a, 0);
  ssh_mprz_set_str(&b, ssh_ecp_fixed_params[i].b, 0);
  ssh_mprz_set_str(&c, ssh_ecp_fixed_params[i].c, 0);
  ssh_mprz_set_str(&x, ssh_ecp_fixed_params[i].px, 0);
  ssh_mprz_set_str(&y, ssh_ecp_fixed_params[i].py, 0);

  /* Set up a curve. */
  if (!ssh_ecp_set_curve(E, &q, &a, &b, &c))
    {
      ssh_ecp_clear_curve(E);
      rv = FALSE;
      goto error;
    }

  ssh_ecp_init_point(P, E);
  ssh_ecp_set_point(P, &x, &y, 1);

  ssh_mprz_init(n);
  ssh_mprz_set_str(n, ssh_ecp_fixed_params[i].n, 0);

  /* Clear variables. */
  rv = TRUE;
error:
  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&c);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&x);
  ssh_mprz_clear(&y);
  return rv;
}

#endif /* SSHDIST_MATH_ECP */
#endif /* SSHDIST_CRYPT_ECP */
/* ecpfix.c */
