# Control Plane Index

| Capability Package | Broker Ref | Policy Ref | Executor Ref | Provider Requirements |
| --- | --- | --- | --- | --- |
| browser.automation | browser-broker | browser-interactive | sandbox-broker-isolated | - |
| exec.run | exec-broker | exec-rootonly | sandbox-high-risk | settings-provider |
| external.write | external-router-broker | write-mediumrisk | sandbox-broker-isolated | settings-provider, notes-provider |
| file.read | file-broker | readonly-mediumrisk | local-readonly | file-manager-provider |
| file.write | file-broker | write-mediumrisk | sandbox-broker-isolated | file-manager-provider |
| info.lookup | info-broker | readonly-lowrisk | local-readonly | settings-provider, file-manager-provider, calculator-provider, utility-provider |
| message.read | message-broker | readonly-mediumrisk | local-readonly | - |
| message.send | message-broker | write-mediumrisk | sandbox-broker-isolated | - |
| network.fetch.readonly | info-broker | network-readonly | local-readonly | - |
