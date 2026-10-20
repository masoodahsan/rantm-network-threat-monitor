#include "baseline.h"

void baseline_update(SourceProfile *profile, double packets_per_second)
{
    const double alpha = 0.20;
    if (profile == 0) return;
    if (profile->completed_windows == 0)
        profile->baseline_packets_per_second = packets_per_second;
    else
        profile->baseline_packets_per_second =
            alpha * packets_per_second +
            (1.0 - alpha) * profile->baseline_packets_per_second;
    profile->completed_windows++;
}

double baseline_deviation_score(const SourceProfile *profile, double current_rate)
{
    double baseline;
    if (profile == 0 || profile->completed_windows < 3) return 0.0;
    baseline = profile->baseline_packets_per_second;
    if (baseline < 1.0) baseline = 1.0;
    if (current_rate <= baseline * 2.0) return 0.0;
    if (current_rate <= baseline * 4.0) return 10.0;
    if (current_rate <= baseline * 8.0) return 20.0;
    return 30.0;
}
