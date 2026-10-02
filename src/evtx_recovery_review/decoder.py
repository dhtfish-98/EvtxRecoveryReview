"""Recovery bookkeeping around the exact frozen decoder; no changed token rules."""
from ._record_core.binxml import BinXML


class Decoder(BinXML):
    def __init__(self, *arguments):
        super().__init__(*arguments)
        self.pi_seen = False

    def pi(self, cursor):
        self.pi_seen = True
        return super().pi(cursor)

    def checkpoint(self):
        return tuple(len(mapping) for mapping in self.maps())

    def maps(self):
        return (self.names, self.templates, self.name_links, self.template_links)

    def rollback(self, lengths):
        # Decoder caches only append new definitions and reject overwrites.
        for mapping, length in zip(self.maps(), lengths):
            while len(mapping) > length:
                mapping.popitem()

    def copy_for_slack(self, ledger):
        # Charge before copying maps so many overlapping candidates cannot cause
        # repeated unbounded cache copies. ASTs are immutable during binding.
        ledger.consume_bytes(sum(len(mapping) for mapping in self.maps()) * 64, self.start)
        result = Decoder(self.raw, self.start, self.start + 65536, ledger)
        for target, source in zip(result.maps(), self.maps()):
            target.update(source)
        return result
