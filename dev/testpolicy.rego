package testpolicy

deny[msg]{
	input.exitcode != 0
    msg := "non-zero exit code"
}

deny[msg]{
	input.cmd[0] != "bash"
    msg := "bash not used"
}