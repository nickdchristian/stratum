import math
import re
from collections import Counter


def get_bucket_name_predictability(bucket_name: str) -> str:
    """
    AWS recommends to not create buckets that are 'predictable'
    and includes a GUID in order to prevent some potential attacks,
    such as name squatting. This function uses Shannon Entropy to
    measure 'predictability'.
    """

    entropy = 0

    has_guid_fragment = bool(re.search(r"[a-f0-9]{8,}", bucket_name))

    character_frequency = Counter(bucket_name)
    bucket_name_length = len(bucket_name)

    for frequency in character_frequency.values():
        probability = frequency / bucket_name_length
        entropy -= probability * math.log2(probability)

    print(has_guid_fragment)
    print(entropy)

    if has_guid_fragment and entropy > 3.0:
        return "LOW"
    elif entropy < 2.5 or len(bucket_name) < 8:
        return "HIGH"
    else:
        return "MODERATE"
