# Remote controlled Hot Air Balloon

A Docker proxy for running Docker builds within Fly's infrastructure.

This is deployed as an independent Fly application when running `flyctl deploy --remote-only` for the first time.
Then, flyctl will use this remote builder for all applications deployed by the organization.


