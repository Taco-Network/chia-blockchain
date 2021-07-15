import functools
from typing import List, Optional

from blspy import AugSchemeMPL, G1Element, G2Element, GTElement
from chia.util.hash import std_hash
from chia.util.lru_cache import LRUCache


def get_pairings(cache: LRUCache, pks: List[G1Element], msgs: List[bytes], force: bool) -> List[GTElement]:
    pairings: List[GTElement] = []
    missing_count: int = 0
    for pk, msg in zip(pks, msgs):
        aug_msg: bytes = bytes(pk) + msg
        h: bytes = bytes(std_hash(aug_msg))
        pairing: Optional[GTElement] = cache.get(h)
        if pairing is None:
            missing_count += 1
            # Heuristic to avoid more expensive sig validation with pairing
            # cache when it's empty and cached pairings won't be useful later
            # (e.g. while syncing)
            if not force and missing_count > len(pks) // 2:
                return []
        pairings.append(pairing)

    for i, pairing in enumerate(pairings):
        if pairing is None:
            aug_msg = bytes(pks[i]) + msgs[i]
            aug_hash: G2Element = AugSchemeMPL.g2_from_message(aug_msg)
            pairing = pks[i].pair(aug_hash)

            h = bytes(std_hash(aug_msg))
            cache.put(h, pairing)
            pairings[i] = pairing

    return pairings


local_cache = LRUCache(10000)


def aggregate_verify(pks: List[G1Element], msgs: List[bytes], sig: G2Element, force: bool = False):
    if len(pks) == 0 and sig == G2Element():
        return True
    pairings: List[GTElement] = get_pairings(local_cache, pks, msgs, force)
    if len(pairings) == 0:
        return AugSchemeMPL.aggregate_verify(pks, msgs, sig)

    pairings_prod: GTElement = functools.reduce(GTElement.__mul__, pairings)
    return pairings_prod == sig.pair(G1Element.generator())
