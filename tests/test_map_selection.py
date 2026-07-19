"""Wybor mapy licznikow sposrod map programu.

Regresja z 2026-07-19: `refresh_map_id` bralo `map_ids[0]`, co dzialalo wylacznie
dopoki program mial DOKLADNIE JEDNA mape. Dolozenie tablicy licznikow odrzucen
zamienilo wybor w rzut moneta, a przegrana byla CICHA — klucz mapy licznikow ma
20 bajtów i parser '<BBHH2xIII', klucz tablicy ma 4, wiec czytnik nie produkowal
nic, podczas gdy jadro liczylo 126 Mb/s ruchu.
"""
import pytest

from udp_analyzer.ebpf import UDP_INGRESS_MAP_NAME, BpftoolMapReader


class FakeRunner:
    """Zwraca przygotowane wyjscia `bpftool -j prog show` / `map show`."""

    def __init__(self, programs, maps):
        self.programs, self.maps = programs, maps
        self.calls = []

    def run_json(self, argv, sudo=False):
        self.calls.append(argv)
        return self.maps if "map" in argv else self.programs


PROG = [{"id": 22, "name": "udp_ingress", "map_ids": [3, 9]}]
#: jadro obcina nazwy map do 15 znakow — stad 'udp_ingress_cou', nie '...counters'
MAPS = [
    {"id": 9, "name": "udp_ingress_dro"},      # tablica powodow odrzucen
    {"id": 3, "name": "udp_ingress_cou"},      # wlasciwa mapa licznikow
]


def test_picks_the_counters_map_not_the_first_one():
    r = FakeRunner(PROG, MAPS)
    assert BpftoolMapReader(runner=r).refresh_map_id() == 3


def test_order_of_map_ids_does_not_matter():
    """Kolejnosc w `map_ids` zalezy od loadera — nie wolno na niej polegac."""
    for ids in ([3, 9], [9, 3]):
        r = FakeRunner([{"id": 22, "name": "udp_ingress", "map_ids": ids}], MAPS)
        assert BpftoolMapReader(runner=r).refresh_map_id() == 3


def test_truncated_kernel_name_still_matches():
    """UDP_INGRESS_MAP_NAME ma 20 znakow, jadro pokazuje 15."""
    assert len(UDP_INGRESS_MAP_NAME) > 15
    r = FakeRunner(PROG, MAPS)
    assert BpftoolMapReader(runner=r).refresh_map_id() == 3


def test_missing_counters_map_raises_instead_of_guessing():
    """Cichy zly wybor kosztowal nas produkcyjna cisze — ma byc glosno."""
    r = FakeRunner([{"id": 22, "name": "udp_ingress", "map_ids": [9]}],
                   [{"id": 9, "name": "udp_ingress_dro"}])
    with pytest.raises(RuntimeError) as exc:
        BpftoolMapReader(runner=r).refresh_map_id()
    msg = str(exc.value)
    assert "udp_ingress_dro" in msg and "udp_ingress_cou" in msg, \
        "komunikat ma pokazywac, co znaleziono i czego szukano"


def test_newest_program_wins_when_an_orphan_lingers():
    """Osierocony filtr sprzed przeladowania nie moze przejac odczytu."""
    r = FakeRunner(
        [{"id": 7, "name": "udp_ingress", "map_ids": [1]},      # stary
         {"id": 22, "name": "udp_ingress", "map_ids": [3, 9]}],  # biezacy
        MAPS + [{"id": 1, "name": "udp_ingress_cou"}],
    )
    assert BpftoolMapReader(runner=r).refresh_map_id() == 3
