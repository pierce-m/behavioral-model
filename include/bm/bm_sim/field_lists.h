/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

//! @file field_lists.h

#ifndef BM_BM_SIM_FIELD_LISTS_H_
#define BM_BM_SIM_FIELD_LISTS_H_

#include <boost/functional/hash.hpp>
#include <boost/variant.hpp>

#include <utility>  // for pair<>
#include <vector>
#include <unordered_set>

#include "phv_forward.h"

namespace bm {

//! Corresponds to a `field_list` object in P4 v1.0.2. Some targets -this is the
//! case for the simple switch target- need to access FieldList instances (using
//! Context::get_field_list() or Switch::get_field_list()). The simple switch
//! target uses this to implement metadata carry when cloning a packet.
class FieldList {
 public:
  struct field_t {
    header_id_t header;
    int offset;

    bool operator==(const field_t& other) const {
      return header == other.header && offset == other.offset;
    }
    bool operator!=(const field_t& other) const {
      return !(*this == other);
    }
  };

  struct constant_t {
    int value;
    size_t nbits;

    bool operator==(const constant_t& other) const {
      return value == other.value && nbits == other.nbits;
    }
    bool operator!=(const constant_t& other) const {
      return !(*this == other);
    }
  };

 public:
  using field_list_member_t = boost::variant<field_t, constant_t>;
  using iterator = std::vector<field_list_member_t>::iterator;
  using const_iterator = std::vector<field_list_member_t>::const_iterator;
  using reference = std::vector<field_list_member_t>::reference;
  using const_reference = std::vector<field_list_member_t>::const_reference;
  using size_type = size_t;

 public:
  void push_back_field(header_id_t header, int field_offset) {
    field_t f = {header, field_offset};
    fields.push_back(field_list_member_t(f));
    fields_set.insert(field_list_member_t(f));
  }

  void push_back_constant(int value, size_t nbits) {
    constant_t c = {value, nbits};
    fields.push_back(field_list_member_t(c));
    fields_set.insert(field_list_member_t(c));
  }

  // iterators

  //! NC
  iterator begin() { return fields.begin(); }

  //! NC
  const_iterator begin() const { return fields.begin(); }

  //! NC
  iterator end() { return fields.end(); }

  //! NC
  const_iterator end() const { return fields.end(); }

  //! Returns true if the FieldList contains the given field, identified by the
  //! header id and the offset of the field in the header
  bool contains(header_id_t header, int field_offset) const {
    field_t f = {header, field_offset};
    auto it = fields_set.find(field_list_member_t(f));
    return it != fields_set.end();
  }

 private:
  struct FieldKeyHash {
    std::size_t operator()(const field_list_member_t& flm) const {
      std::size_t seed = 0;
      if (flm.type() == typeid(field_t)) {
        field_t f = boost::get<field_t>(flm);
        boost::hash_combine(seed, f.header);
        boost::hash_combine(seed, f.offset);
      } else if (flm.type() == typeid(constant_t)) {
        constant_t c = boost::get<constant_t>(flm);
        boost::hash_combine(seed, c.value);
        boost::hash_combine(seed, c.nbits);
      }
      return seed;
    }
  };

 private:
  std::vector<field_list_member_t> fields{};
  std::unordered_set<field_list_member_t, FieldKeyHash> fields_set{};
};

}  // namespace bm

#endif  // BM_BM_SIM_FIELD_LISTS_H_
