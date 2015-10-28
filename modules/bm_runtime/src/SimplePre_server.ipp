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

#include "SimplePre.h"

#include <bm_sim/simple_pre.h>

namespace bm_runtime { namespace simple_pre {

#ifndef USING_FACEBOOK_THRIFT                 
  #define WHAT_STORE(what0, err)              \
    what0 = (McOperationErrorCode::type) err; 
#else                                         
  #define WHAT_STORE(what0, err)              \
    what0 = (McOperationErrorCode) err;       
#endif                                        
    

class SimplePreHandler : virtual public SimplePreIf {
public:
  SimplePreHandler(Switch *sw) 
    : switch_(sw) {
    pre = sw->get_component<McSimplePre>();
    assert(pre != nullptr);
  }

  BmMcMgrpHandle bm_mc_mgrp_create(const BmMcMgrp mgrp) {
    printf("bm_mc_mgrp_create\n");
    McSimplePre::mgrp_hdl_t mgrp_hdl;
    McSimplePre::McReturnCode error_code =
      pre->mc_mgrp_create(mgrp, &mgrp_hdl);
    if(error_code != McSimplePre::SUCCESS) {
      InvalidMcOperation imo;
      imo.what0 = (McOperationErrorCode) error_code;
      WHAT_STORE(imo.what0, error_code)
      throw imo;
    }
    return mgrp_hdl;
  }

  void bm_mc_mgrp_destroy(const BmMcMgrpHandle mgrp_handle) {
    printf("bm_mc_mgrp_destroy\n");
    McSimplePre::McReturnCode error_code =
      pre->mc_mgrp_destroy(mgrp_handle);
    if(error_code != McSimplePre::SUCCESS) {
      InvalidMcOperation imo;
      WHAT_STORE(imo.what0, error_code)
      throw imo;
    }
  }

  BmMcL1Handle bm_mc_node_create(const BmMcRid rid, const BmMcPortMap& port_map) {
    printf("bm_mc_node_create\n");
    McSimplePre::l1_hdl_t l1_hdl;
    McSimplePre::McReturnCode error_code =
      pre->mc_node_create(rid, port_map, &l1_hdl);
    if(error_code != McSimplePre::SUCCESS) {
      InvalidMcOperation imo;
      WHAT_STORE(imo.what0, error_code)
      throw imo;
    }
    return l1_hdl;
  }

  void bm_mc_node_associate(const BmMcMgrpHandle mgrp_handle, const BmMcL1Handle l1_handle) {
    printf("bm_mc_node_associate\n");
    McSimplePre::McReturnCode error_code =
      pre->mc_node_associate(mgrp_handle, l1_handle);
    if(error_code != McSimplePre::SUCCESS) {
      InvalidMcOperation imo;
      WHAT_STORE(imo.what0, error_code)
      throw imo;
    }
  }

  void bm_mc_node_dissociate(const BmMcMgrpHandle mgrp_handle, const BmMcL1Handle l1_handle) {
    printf("bm_mc_node_dissociate\n");
    McSimplePre::McReturnCode error_code =
      pre->mc_node_dissociate(mgrp_handle, l1_handle);
    if(error_code != McSimplePre::SUCCESS) {
      InvalidMcOperation imo;
      WHAT_STORE(imo.what0, error_code)
      throw imo;
    }
  }

  void bm_mc_node_destroy(const BmMcL1Handle l1_handle) {
    printf("bm_mc_node_destroy\n");
    McSimplePre::McReturnCode error_code =
      pre->mc_node_destroy(l1_handle);
    if(error_code != McSimplePre::SUCCESS) {
      InvalidMcOperation imo;
      WHAT_STORE(imo.what0, error_code)
      throw imo;
    }
  }

  void bm_mc_node_update(const BmMcL1Handle l1_handle, const BmMcPortMap& port_map) {
    printf("bm_mc_node_update\n");
    McSimplePre::McReturnCode error_code = pre->mc_node_update(
        l1_handle, McSimplePre::PortMap(port_map)
    );
    if(error_code != McSimplePre::SUCCESS) {
      InvalidMcOperation imo;
      WHAT_STORE(imo.what0, error_code)
      throw imo;
    }
  }

private:
  Switch *switch_{nullptr};
  std::shared_ptr<McSimplePre> pre{nullptr};
};

} }
