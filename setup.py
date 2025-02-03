from setuptools import Extension, setup  # type: ignore

fastmath = Extension(
    "mlkem.fastmath",
    sources=["mlkem/math/fastmathmodule.c"],
    extra_compile_args=["-std=c99"],
)

setup(
    ext_modules=[fastmath],
)
