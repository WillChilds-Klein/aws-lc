import typing

from aws_cdk import aws_codebuild as codebuild, Environment, Stack
from constructs import Construct

from cdk.components import PruneStaleGitHubBuilds
from util.metadata import (
    STAGING_GITHUB_REPO_OWNER,
    STAGING_GITHUB_REPO_NAME,
    PRE_PROD_ACCOUNT,
    GITHUB_REPO_OWNER,
    GITHUB_REPO_NAME,
    GITHUB_PUSH_CI_BRANCH_TARGETS,
)


class AwsLcBaseCiStack(Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        env: typing.Union[Environment, typing.Dict[str, typing.Any]],
        ignore_failure: typing.Optional[bool] = False,
        timeout: typing.Optional[int] = 60,
        **kwargs
    ) -> None:
        super().__init__(scope, id, env=env, **kwargs)
        self.ignore_failure = ignore_failure
        self.timeout = timeout
        self.env = env

        self.github_repo_owner = (
            STAGING_GITHUB_REPO_OWNER
            if (env.account == PRE_PROD_ACCOUNT)
            else GITHUB_REPO_OWNER
        )
        self.github_repo_name = (
            STAGING_GITHUB_REPO_NAME
            if (env.account == PRE_PROD_ACCOUNT)
            else GITHUB_REPO_NAME
        )

        self.git_hub_source = codebuild.Source.git_hub(
            owner=self.github_repo_owner,
            repo=self.github_repo_name,
            webhook=True,
            webhook_filters=[
                codebuild.FilterGroup.in_event_of(
                    codebuild.EventAction.PULL_REQUEST_CREATED,
                    codebuild.EventAction.PULL_REQUEST_UPDATED,
                    codebuild.EventAction.PULL_REQUEST_REOPENED,
                    # Temporarily allowlist the webhook to members of the Github teams:
                    # https://github.com/orgs/aws/teams/aws-lc-dev
                    # https://github.com/orgs/aws/teams/aws-lc-contributor
                ).and_actor_account_is(
                    "(215225139|549813|3589880|11924508|25055813|38119460|41167468|50673096|66388554|69484052|"
                    "103147162|107728331|159580656|3596374|7552310|7660279|13040499|26892988|44320407|68056884)"
                ),
                codebuild.FilterGroup.in_event_of(
                    codebuild.EventAction.PUSH
                ).and_branch_is(GITHUB_PUSH_CI_BRANCH_TARGETS),
            ],
            webhook_triggers_batch_build=True,
        )
