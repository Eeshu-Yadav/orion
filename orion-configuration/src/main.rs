#![allow(clippy::print_stdout)]
// SPDX-FileCopyrightText: © 2025 kmesh authors
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 kmesh authors
//
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//

use orion_configuration::{config::Config, options::Options, Result};
use orion_error::ResultExtension;

fn main() -> Result<()> {
    let config = Config::new(&Options::from_path("bootstrap.yaml"))?;
    let yaml = serde_yaml::to_string(&config).context("failed to serialize orion config")?;
    std::fs::write("orion.yaml", yaml.as_bytes())?;
    println!("{yaml}");
    Ok(())
}
