from unittest import TestCase

from mlkem.k_pke import K_PKE
from mlkem.parameter_set import ML_KEM_512


class TestKPKE(TestCase):
    def test_key_gen_ml_kem_512(self) -> None:
        pke = K_PKE(ML_KEM_512)
        d = bytes.fromhex(
            "1EB4400A01629D517974E2CD85B9DEF59082DE508E6F9C2B0E341E12965955CA"
        )
        expected_ek = bytes.fromhex(
            "5B318622F73E6FC6CBA5571D0537894AA890426B835640489AA218972180BB2534BCC477C62CC839135934F3B14CD0808A11557D331103B30F9A8C0CB0FA8F0A2A152E802E48E408087510D5114D4D2399A51530616C7E310528308176D0042710BC8344EC3D4CA810A92978BFABB516D81CAB0753CDF325AC2377A1F96EFC73C15F5AA367A1582A13651B0337C7943C1D54637669686BEBBD392511FFFC9E3A68CBEEC0CE2CF59A8D51C4DE288EB4641DF6610C82D09CDDA418ACD83F0DCA2859B27117E87981AAA8EBA47515812DA2C27ADF9C682E373D5AF294BE3104474B8D14173788965ECCD80322B6CA04240E7D150F2CD4B04066C1924039B9E4A9E06C2B55DBA2FDDABB4065CFE7EBC5AE01CD45C76374683CB1820C34A841836391B9D8C2AA22B29E7436CFCAB789B3CE8AE2700351C1165B7B4F72CC53E913E5668AE75170352A0DE68A5E3819443DB4113161A2019C4930C97011F31540B833E9A890503A7EC3F38C0D94BE3C7501C6161F39099E3CAC0139ACC7271B70D1664A36A89FA4D22857C6C15AD4C52D5C26E23B81DCDA9FD7A49980C5818888AB2538AD91F54E691B7558C63FAE433A7FAB51485989F4335E6187B65041401238AA0A5A932356207796AF2C70363034546F4615499245E1228BFF2C76674634A60C9A04E00FB276C6C00A114BF1B2C8961E740A082940CEEAAB464370BBBB3919C7421BC81C732415A711AA935A4C2C02CB5D0BCBB99CE830EDDBAE4C228E4F095E29FBC27EA2B881697A1D309D28C480C3E9691FB63480BC5C6239B6CCAA41CD52A6209038C2C887BC71C1BD514A0FAA21721A2A5B30ACB168227833A8260422C1F4815EC2ADB207389FB1B817D78FC96063434B6728E18469475DB5D712BC403D8231CF9C8926D0A94B6830881FA5678AD04499F40D5CA83479BA85A70B1196C32A68A6B7FFB40EA6FC3FF020768B91B27F653746546C5E256B14069E827C1616FC7647F8B70F8A32DB551CF715BBB315B7B9BC20FF76847CFC4AEAC23DDC1302EC928CFE40447C761143194DA1415D3D8389F61BAB41EB605729123A320BB54B3B3FBCBC787C46F354C7D7D60F8DFE3729375AEF1891C08A79DE237E39E860061D"
        )

        actual_ek, _ = pke.key_gen(d)

        self.assertEqual(len(expected_ek), len(actual_ek))
        self.assertEqual(expected_ek, actual_ek)
