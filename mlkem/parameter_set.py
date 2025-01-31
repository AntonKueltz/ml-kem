from dataclasses import dataclass


@dataclass
class ParameterSet:
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int


# bit strength / security parameter = 128 bits
ML_KEM_512 = ParameterSet(k=2, eta1=3, eta2=2, du=10, dv=4)
# bit strength / security parameter = 192 bits
ML_KEM_768 = ParameterSet(k=3, eta1=2, eta2=2, du=10, dv=4)
# bit strength / security parameter = 256 bits
ML_KEM_1024 = ParameterSet(k=4, eta1=2, eta2=2, du=11, dv=5)
