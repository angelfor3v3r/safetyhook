#include <boost/ut.hpp>
#include <safetyhook.hpp>

using namespace boost::ut;

static suite<"allocator"> allocator_tests = [] {
    "Allocator reuses freed memory"_test = [] {
        auto allocator = safetyhook::Allocator::create();
        auto first_allocation = allocator->allocate(128);

        expect(first_allocation.has_value());

        auto first_allocation_address = first_allocation->address();
        auto second_allocation = allocator->allocate(256);

        expect(second_allocation.has_value());
        expect(neq(second_allocation->address(), first_allocation_address));

        first_allocation->free();

        auto third_allocation = allocator->allocate(64);

        expect(third_allocation.has_value());
        expect(eq(third_allocation->address(), first_allocation_address));

        auto fourth_allocation = allocator->allocate(64);

        expect(fourth_allocation.has_value());
        expect(eq(fourth_allocation->address(), third_allocation->address() + 64));
    };
};