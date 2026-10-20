#ifndef RISK_ENGINE_H
#define RISK_ENGINE_H
#include "rantm.h"
void risk_calculate(SourceProfile *profile, const RantmConfig *config,
                    RiskResult *result);
#endif
