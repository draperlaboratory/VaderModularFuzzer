#include "GramatronGenerateMutator.hpp"
#include "GramatronRandomMutator.hpp"
#include "GramatronRecursiveMutator.hpp"
#include "GramatronSpliceMutator.hpp"
#include "ModuleTestHelper.hpp"
#include "SimpleStorage.hpp"
#include "gtest/gtest.h"

#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace vmf;
using Walk = std::vector<std::pair<int, int>>;

class GramatronMutatorTest : public testing::Test {
protected:
  void SetUp() override {
    pda = PDA::CreateInstance(GRAMATRON_TEST_PDA);
    ASSERT_NE(pda, nullptr);
    ASSERT_EQ(pda->final_state(), 3);
  }

  void configure(MutatorModule &mutator) {
    mutator.init(*helper.getConfig());
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER,
                                       StorageRegistry::READ_WRITE);
    autKey = registry.registerKey("TEST_CASE_AUT", StorageRegistry::BUFFER,
                                  StorageRegistry::READ_WRITE);
    normalTag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::WRITE_ONLY);
    mutator.registerStorageNeeds(registry);
    storage.configure(&registry, &metadata);
  }

  StorageEntry *entry(const Walk &walk) {
    auto *result = storage.createNewEntry();
    auto *input = static_cast<Array *>(std::malloc(sizeof(Array)));
    initArray(input, walk.size());
    for (const auto &step : walk) {
      const auto &transition = pda->state_ptr()[step.first].ptr[step.second];
      insertArray(input, step.first, transition.term, transition.term_len, step.second);
    }
    storeTestCase(result, input, testCaseKey, autKey);
    return result;
  }

  void saveDonor(const Walk &walk) {
    auto *donor = entry(walk);
    storage.saveEntry(donor);
    donor->addTag(normalTag);
  }

  StorageEntry *mutate(MutatorModule &mutator, StorageEntry *base, unsigned seed) {
    VmfRand::getInstance()->initSeed(seed);
    auto *result = storage.createNewEntry();
    mutator.mutateTestCase(storage, base, result, testCaseKey);
    return result;
  }

  std::string bytes(StorageEntry *result) {
    return {result->getBufferPointer(testCaseKey),
            static_cast<size_t>(result->getBufferSize(testCaseKey))};
  }

  void expectOutput(StorageEntry *result, const std::string &expected,
                    const Walk &expectedWalk) {
    ASSERT_GT(result->getBufferSize(autKey), 0);
    auto *input = read_input(pda->state_ptr(), result->getBufferPointer(autKey));
    Walk actual;
    std::string fingerprint = bytes(result);
    for (size_t i = 0; i < input->used; ++i) {
      const auto &step = input->start[i];
      actual.emplace_back(step.state, step.trigger_idx);
      fingerprint += "/" + std::to_string(step.state) + ":" +
                     std::to_string(step.trigger_idx);
    }
    std::free(input->start);
    std::free(input);
    RecordProperty("output", fingerprint);
    EXPECT_EQ(bytes(result), expected);
    EXPECT_EQ(actual, expectedWalk);
  }

  void expectBranch(StorageEntry *result) {
    if (bytes(result) == "AE")
      expectOutput(result, "AE", {{0, 0}, {1, 1}});
    else
      expectOutput(result, "ABC", abc);
  }

  const Walk abc{{0, 0}, {1, 0}, {2, 0}};
  StorageRegistry registry;
  StorageRegistry metadata;
  SimpleStorage storage{"storage"};
  ModuleTestHelper helper;
  PDA *pda = nullptr;
  int testCaseKey;
  int autKey;
  int normalTag;
};

TEST_F(GramatronMutatorTest, GenerateEmitsCompleteWalk) {
  GramatronGenerateMutator mutator("generate");
  configure(mutator);
  expectBranch(mutate(mutator, nullptr, 23));
}

TEST_F(GramatronMutatorTest, RandomRegeneratesSuffix) {
  GramatronRandomMutator mutator("random");
  configure(mutator);
  expectBranch(mutate(mutator, entry(abc), 23));
}

TEST_F(GramatronMutatorTest, SpliceUsesSharedState) {
  GramatronSpliceMutator mutator("splice");
  configure(mutator);
  saveDonor({{1, 1}});
  expectOutput(mutate(mutator, entry(abc), 23), "AE", {{0, 0}, {1, 1}});
}

TEST_F(GramatronMutatorTest, SpliceWithoutSharedStateKeepsBase) {
  GramatronSpliceMutator mutator("splice");
  configure(mutator);
  saveDonor({{5, 0}});
  expectOutput(mutate(mutator, entry(abc), 23), "ABC", abc);
}

TEST_F(GramatronMutatorTest, RecursiveWithoutRepeatedStatesUsesRandomFallback) {
  GramatronRecursiveMutator mutator("recursive");
  configure(mutator);
  expectBranch(mutate(mutator, entry(abc), 23));
}

TEST_F(GramatronMutatorTest, RecursiveUsesBothOrdersOfRepeatedStateEndpoints) {
  GramatronRecursiveMutator mutator("recursive");
  configure(mutator);
  auto *base = entry({{4, 0}, {4, 1}, {2, 0}});
  bool forward = false;
  bool reverse = false;
  auto *rng = VmfRand::getInstance();
  for (unsigned seed = 0; seed < 64 && !(forward && reverse); ++seed) {
    rng->initSeed(seed);
    const bool swapped = rng->randBelow(2) == 0;
    const int repetitions = rng->randBelow(RECUR_THRESHOLD);
    if ((!swapped && repetitions == 1) || (swapped ? reverse : forward))
      continue;
    SCOPED_TRACE(seed);
    const int loops = repetitions + (swapped ? 2 : 0);
    Walk expected(loops, {4, 0});
    expected.emplace_back(4, 1);
    expected.emplace_back(2, 0);
    expectOutput(mutate(mutator, base, seed), std::string(loops, 'L') + "XC", expected);
    (swapped ? reverse : forward) = true;
  }
  EXPECT_TRUE(forward);
  EXPECT_TRUE(reverse);
}
} // namespace
