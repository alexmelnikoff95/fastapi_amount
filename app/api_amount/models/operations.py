from datetime import date
from decimal import Decimal
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class OperationKind(str, Enum):
    INCOME = 'income' '''заработано'''
    OUTCOME = 'outcome' '''потрачено'''


class Operation(BaseModel):
    date: date
    kind: OperationKind
    amount: Decimal
    description: Optional[str]

    class Config:
        orm_mode = True


class OperationCreate(Operation):
    pass


class OperationUpdate(Operation):
    pass
