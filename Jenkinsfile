#!/usr/bin/env groovy

import groovy.json.JsonSlurperClassic

@Library('sec_ci_libs@v2-latest') _

def master_branches = ["master", ] as String[]

if (master_branches.contains(env.BRANCH_NAME)) {
    // Rebuild main branch once a day
    properties([
        pipelineTriggers([cron('H H * * *')])
    ])
}

// http://stackoverflow.com/a/38439681
@NonCPS
def jsonParse(def json) {
    new groovy.json.JsonSlurperClassic().parseText(json)
}


def builders = [:]

builders['adminrouter'] = {
    task_wrapper('mesos-sec', master_branches, '8b793652-f26a-422f-a9ba-0d1e47eb9d89', '#dcos-security-ci') {
        stage('Admin Router: Cleanup workspace') {
            deleteDir()
        }

        stage('Admin Router: Checkout') {
            def repo_url
            def repo_sha

            dir("dcos-ee") {
                checkout scm

                // Gather some info about upstream repository
                def upstream_config =  jsonParse(readFile("packages/upstream.json"))
                repo_url = upstream_config['git']
                repo_branch = upstream_config['ref_origin']
            }

            dir("dcos-open") {
                git branch: repo_branch, credentialsId: 'a7ac7f84-64ea-4483-8e66-bb204484e58f', poll: false, url: repo_url
                sh 'echo `pwd` > ../dcos-ee/packages/adminrouter/extra/src/.dcos-open.path'
            }
        }

        dir("dcos-ee/packages/adminrouter/extra/src/") {
            stage('Admin Router: Apply EE overlay on top of Open') {
                sh 'make apply-open'
            }

            stage('Admin Router: Prepare devkit container') {
                sh 'make update-devkit'
            }

            try {
                stage('make check-api-docs') {
                    sh 'make check-api-docs'
                }

                stage('Admin Router: make lint') {
                    sh 'make lint'
                }

                stage('Admin Router: make test') {
                    sh 'make test'
                }

            } finally {
                stage('Admin Router: archive build artifacts') {
                    archiveArtifacts artifacts: 'test-harness/logs/*.log', allowEmptyArchive: true, excludes: 'test_harness/', fingerprint: true
                }

                stage('Admin Router: Cleanup docker container'){
                    sh 'make clean-containers'
                    sh "docker rmi -f adminrouter-devkit || true"
                }
            }
        }
    }
}

builders['gen_extra'] = {
    task_wrapper('mesos-sec', master_branches, '8b793652-f26a-422f-a9ba-0d1e47eb9d89', '#dcos-security-ci') {
        stage('gen_extra: Cleanup workspace') {
            deleteDir()
        }

        stage('gen_extra: Checkout') {
            dir("dcos-ee-gen_extra") {
                checkout scm
            }
        }

        dir("dcos-ee-gen_extra/gen_extra") {
            stage('gen_extra: Prepare devkit container') {
                sh 'make update-devkit'
            }

            try {
                stage('gen_extra: make test') {
                    sh 'make test'
                }
            } finally {
                stage('gen_extra: Cleanup docker container'){
                    sh 'make clean-containers'
                    sh "docker rmi -f dcos-ee-gen_extra-devkit || true"
                }
            }
        }
    }
}

parallel builders
