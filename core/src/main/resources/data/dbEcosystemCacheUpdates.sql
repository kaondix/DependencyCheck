UPDATE cpeEcosystemCache set ecosystem='MULTIPLE' where vendor = 'apache' and product = 'hadoop' and ecosystem != 'MULTIPLE';
UPDATE cpeEcosystemCache set ecosystem='MULTIPLE' where vendor = 'apache' and product = 'ranger' and ecosystem != 'MULTIPLE';
UPDATE cpeEcosystemCache set ecosystem='NATIVE' where vendor = 'git' and product = 'git' and ecosystem != 'NATIVE';
UPDATE cpeEcosystemCache set ecosystem='NATIVE' where vendor = 'python' and product = 'python' and ecosystem != 'NATIVE';
UPDATE cpeEcosystemCache set ecosystem='NATIVE' where vendor = 'python_software_foundation' and product = 'python' and ecosystem != 'NATIVE';
UPDATE cpeEcosystemCache set ecosystem='NATIVE' where vendor = 'python' and product = 'python' and ecosystem != 'NATIVE';