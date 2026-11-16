from dataclasses import dataclass


@dataclass(frozen=True)
class Indicator:
    name: str
    explanation: str
    points: int
    severity: str = "medium"

    def as_dict(self):
        return {
            "name": self.name,
            "explanation": self.explanation,
            "points": self.points,
            "severity": self.severity,
        }
