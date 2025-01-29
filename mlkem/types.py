from abc import abstractmethod
from typing import Protocol, Self


# the entries of a matrix must have a type supporting addition
# define that interface via this protocol
class Field(Protocol):
    @abstractmethod
    def __add__(self, other: Self) -> Self:
        pass

    @abstractmethod
    def __mul__(self, other: Self) -> Self:
        pass
