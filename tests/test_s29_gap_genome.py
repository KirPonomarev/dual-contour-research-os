from __future__ import annotations
from dataclasses import replace
import inspect
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from research_bridge.evolution import (EvolutionError,EvolutionGenomePolicy,GenomeComponent,OperationalGapSignal,build_genome_snapshot,mine_mutation_candidates)  # noqa:E402

PROFILE=ROOT/'provenance'/'evolution-genome-gap-miner-v1.json'
SHA='bd35130dc90e252773359973f77e4a8e4cc9cdc5a746c1ff362d1bee8a599c07'

class GapGenomeTests(unittest.TestCase):
 def setUp(self):
  self.policy=EvolutionGenomePolicy(PROFILE,expected_profile_sha256=SHA)
  self.denies=tuple(sorted(self.policy.required_deny_invariants))
  self.components=(
   GenomeComponent('component:ledger','version:v1','1'*64,(),self.denies),
   GenomeComponent('component:evolution','version:v1','2'*64,('component:ledger',),self.denies),
   GenomeComponent('component:operator','version:v1','3'*64,('component:evolution',),self.denies),)
  self.genome=build_genome_snapshot(self.policy,subject_ref='git:'+'a'*40,components=self.components)
 def gap(self,index=1,kind='REPLAY_HARDENING',target='component:ledger'):
  return OperationalGapSignal(f'gap:{index}',target,'replay-gap','harden-replay',kind,(f'evidence:{index}',),('extra-deny',))
 def test_deterministic_opportunity_complete_blast_and_archive_provenance(self):
  first=mine_mutation_candidates(self.policy,self.genome,(self.gap(),))
  second=mine_mutation_candidates(self.policy,self.genome,(self.gap(),))
  self.assertEqual(first,second); proposal=first.proposals[0]
  self.assertEqual(proposal.blast_radius_refs,('component:evolution','component:ledger','component:operator'))
  self.assertIn('evidence:1',first.provenance_refs); self.assertEqual(first.applied_count,0)
  self.assertFalse(first.side_effects); self.assertFalse(first.grants_authority)
 def test_every_forbidden_kind_parks_without_proposal(self):
  for kind in self.policy.forbidden_mutation_kinds:
   with self.subTest(kind=kind):
    archive=mine_mutation_candidates(self.policy,self.genome,(self.gap(kind=kind),))
    self.assertEqual(archive.proposals,()); self.assertEqual(archive.parked_gap_refs,('gap:1',))
    self.assertEqual(archive.opportunities[0].status,'PARKED_FORBIDDEN')
 def test_safe_proposal_retains_and_only_grows_deny_invariants(self):
  proposal=mine_mutation_candidates(self.policy,self.genome,(self.gap(),)).proposals[0]
  self.assertTrue(self.policy.required_deny_invariants <= set(proposal.retained_deny_invariants))
  self.assertIn('extra-deny',proposal.retained_deny_invariants)
  self.assertFalse(proposal.executable_payload_present); self.assertFalse(proposal.mutation_applied)
  self.assertFalse(proposal.generated_code_executed); self.assertEqual(proposal.canonical_writes,0)
  self.assertFalse(proposal.grants_authority); self.assertNotIn('payload',inspect.signature(OperationalGapSignal).parameters)
 def test_missing_deny_unknown_dependency_and_cycle_fail_closed(self):
  with self.assertRaises(EvolutionError): build_genome_snapshot(self.policy,subject_ref='git:'+'a'*40,components=(replace(self.components[0],deny_invariants=self.denies[1:]),))
  with self.assertRaises(EvolutionError): build_genome_snapshot(self.policy,subject_ref='git:'+'a'*40,components=(replace(self.components[0],dependency_refs=('component:absent',)),))
  cycle=(replace(self.components[0],dependency_refs=('component:evolution',)),self.components[1])
  with self.assertRaisesRegex(EvolutionError,'cycle'): build_genome_snapshot(self.policy,subject_ref='git:'+'a'*40,components=cycle)
 def test_forged_genome_and_duplicate_gap_fail_closed(self):
  with self.assertRaisesRegex(EvolutionError,'integrity'): mine_mutation_candidates(self.policy,replace(self.genome,genome_sha256='0'*64),(self.gap(),))
  gap=self.gap()
  with self.assertRaisesRegex(EvolutionError,'duplicated'): mine_mutation_candidates(self.policy,self.genome,(gap,gap))
 def test_unknown_kind_is_parked_and_unknown_target_rejected(self):
  archive=mine_mutation_candidates(self.policy,self.genome,(self.gap(kind='UNKNOWN_CHANGE'),))
  self.assertEqual(archive.proposals,()); self.assertEqual(archive.parked_gap_refs,('gap:1',))
  with self.assertRaisesRegex(EvolutionError,'outside'): mine_mutation_candidates(self.policy,self.genome,(self.gap(target='component:absent'),))

if __name__=='__main__': unittest.main()
