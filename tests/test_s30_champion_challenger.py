from __future__ import annotations
from dataclasses import replace
from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from research_bridge.evolution import *  # noqa:E402,F403
GP=ROOT/'provenance'/'evolution-genome-gap-miner-v1.json';GS='bd35130dc90e252773359973f77e4a8e4cc9cdc5a746c1ff362d1bee8a599c07'
CP=ROOT/'provenance'/'champion-challenger-evaluation-v1.json';CS='e31e4aa9f946e54ffe5c91ec887e5f26f44db2569c7edf975504aaa3be7831a8'
class ChallengerTests(unittest.TestCase):
 def setUp(self):
  gp=EvolutionGenomePolicy(GP,expected_profile_sha256=GS);d=tuple(sorted(gp.required_deny_invariants));g=build_genome_snapshot(gp,subject_ref='git:'+'a'*40,components=(GenomeComponent('component:x','version:v1','1'*64,(),d),)); gaps=tuple(OperationalGapSignal(f'gap:{i}','component:x','gap-code','fix-gap','TEST_ADDITION',(f'evidence:{i}',)) for i in range(2));self.archive=mine_mutation_candidates(gp,g,gaps)
  self.policy=ChallengerEvaluationPolicy(CP,expected_profile_sha256=CS);self.cases=tuple(BenchmarkCase(f'case:{i}',f'{i+1:064x}','2'*64,i<2,2<=i<4) for i in range(8));self.benchmark=build_benchmark_snapshot(self.policy,evaluator_ref='evaluator:frozen',evaluator_sha256='3'*64,cases=self.cases);self.champion='champion:v1';self.challenger=self.archive.proposals[0].proposal_ref
 def results(self,candidate,quality=10,info=10,cost=10,latency=10,safety=0,reject_invalid=True):
  return tuple(CandidateCaseResult(candidate,x.case_ref,self.benchmark.benchmark_sha256,quality,info,cost,latency,safety,reject_invalid if x.known_invalid else False) for x in self.cases)
 def evaluate(self,champion=None,challenger=None):
  return evaluate_challenger(self.policy,self.benchmark,self.archive,champion_ref=self.champion,challenger_ref=self.challenger,champion_results=champion or self.results(self.champion),challenger_results=challenger or self.results(self.challenger,11,11,9,9))
 def test_pareto_pass_keeps_every_dimension_and_never_promotes(self):
  r=self.evaluate();self.assertEqual(r.status,'CHAMPION_CHALLENGER_PASS');self.assertEqual(r.pareto_relation,'CHALLENGER_PARETO_DOMINATES');self.assertEqual(len(r.dimensions),5);self.assertIsNone(r.single_scalar_score);self.assertFalse(r.winner_promoted);self.assertFalse(r.mutation_applied);self.assertFalse(r.grants_authority);self.assertEqual(set(r.retained_candidate_refs),{x.proposal_ref for x in self.archive.proposals})
 def test_tradeoff_cannot_be_hidden_by_scalar(self):
  r=self.evaluate(challenger=self.results(self.challenger,quality=20,info=20,cost=20,latency=9));self.assertEqual(r.status,'NOT_ESTABLISHED');self.assertIn('WORSE',{x.challenger_relation for x in r.dimensions});self.assertIsNone(r.single_scalar_score)
 def test_safety_or_known_invalid_failure_vetoes(self):
  for result in (self.results(self.challenger,11,11,9,9,safety=1),self.results(self.challenger,11,11,9,9,reject_invalid=False)):
   with self.subTest(): self.assertEqual(self.evaluate(challenger=result).status,'REJECTED_SAFETY')
 def test_exact_twins_and_bindings_fail_closed(self):
  with self.assertRaises(EvolutionError): self.evaluate(challenger=self.results(self.challenger)[:-1])
  bad=list(self.results(self.challenger));bad[0]=replace(bad[0],benchmark_sha256='0'*64)
  with self.assertRaises(EvolutionError): self.evaluate(challenger=tuple(bad))
 def test_frozen_benchmark_identity_and_hostile_coverage(self):
  with self.assertRaises(EvolutionError): build_benchmark_snapshot(self.policy,evaluator_ref='evaluator:frozen',evaluator_sha256='3'*64,cases=self.cases[:7])
  with self.assertRaises(EvolutionError): evaluate_challenger(self.policy,replace(self.benchmark,benchmark_sha256='0'*64),self.archive,champion_ref=self.champion,challenger_ref=self.challenger,champion_results=self.results(self.champion),challenger_results=self.results(self.challenger))
 def test_forged_archive_or_outside_challenger_fails_closed(self):
  with self.assertRaises(EvolutionError): evaluate_challenger(self.policy,self.benchmark,replace(self.archive,archive_sha256='0'*64),champion_ref=self.champion,challenger_ref=self.challenger,champion_results=self.results(self.champion),challenger_results=self.results(self.challenger))
  with self.assertRaises(EvolutionError): evaluate_challenger(self.policy,self.benchmark,self.archive,champion_ref=self.champion,challenger_ref='proposal:absent',champion_results=self.results(self.champion),challenger_results=self.results('proposal:absent'))
if __name__=='__main__':unittest.main()
