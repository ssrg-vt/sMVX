#include <stdio.h>
#include <fcntl.h>
#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_point.h"
#include "BPatch_function.h"

using namespace std;
using namespace Dyninst;
// Create an instance of class BPatch
BPatch bpatch;

// Different ways to perform instrumentation
typedef enum {
	create,
	attach,
	open_file
} accessType_t;

// Attach, create, or open a file for rewriting
BPatch_addressSpace* startInstrumenting(accessType_t accessType,
					const char* name,
					int pid,
					const char* argv[]) {
	BPatch_addressSpace* handle = NULL;

	switch(accessType) {
		case create:
			handle = bpatch.processCreate(name, argv);
			if (!handle) { fprintf(stderr, "processCreate failed\n"); }
		break;
		case attach:
			handle = bpatch.processAttach(name, pid);
			if (!handle) { fprintf(stderr, "processAttach failed\n"); }
		break;
		case open_file:
			// Open the binary file and all dependencies
			handle = bpatch.openBinary(name, true);
			if (!handle) { fprintf(stderr, "openBinary failed\n"); }
		break;
	}
return handle;
}

// Find a point at which to insert instrumentation
std::vector<BPatch_point*>* findPoint(BPatch_addressSpace* app,
				      const char* name,
				      BPatch_procedureLocation loc) {
	std::vector<BPatch_function*> functions;
	std::vector<BPatch_point*>* points;

	// Scan for functions named "name"
	BPatch_image* appImage = app->getImage();
	appImage->findFunction(name, functions);
	if (functions.size() == 0) {
		fprintf(stderr, "No function %s\n", name);
		return points;
	} else if (functions.size() > 1) {
		fprintf(stderr, "More than one %s; using the first one\n", name);
	}
	// Locate the relevant points
	points = functions[0]->findPoint(loc);
	return points;
}

// Create and insert an increment snippet
bool createAndInsertSnippet(BPatch_addressSpace* app,
			    std::vector<BPatch_point*>* points) {
	BPatch_image* appImage = app->getImage();
	//// Create an increment snippet
	//BPatch_variableExpr* intCounter =
	//	app->malloc(*(appImage->findType("int")), "myCounter");
	//BPatch_arithExpr addOne(BPatch_assign,
	//			*intCounter,
	//			BPatch_arithExpr(BPatch_plus,
	//					 *intCounter,
	//			BPatch_constExpr(1)));
	BPatch_addressSpace* libhandle = NULL;
	libhandle = bpatch.openBinary("liblightweight_mvx.so", true);
	if (!libhandle) { fprintf(stderr, "open liblightweight mvx library failed\n"); }

	BPatch_image* libImage = libhandle->getImage();

	std::vector<BPatch_function*> mvx_func;
	libImage->findFunction("run_lightweight_mvx", mvx_func);
	if (mvx_func.size() == 0) {
		fprintf(stderr, "Could not find run_lightweight_mvx\n");
		return false;
	}

	std::vector<BPatch_snippet*> callArgs;
	// Construct a function call snippet
	BPatch_funcCallExpr mvxCall(*(mvx_func[0]), callArgs);

	// Insert the snippet
	if (!app->insertSnippet(mvxCall, *points)) {
		fprintf(stderr, "insertSnippet failed\n");
		return false;
	}
	return true;
}

// Create and insert a printf snippet
bool createAndInsertSnippet2(BPatch_addressSpace* app,
			     std::vector<BPatch_point*>* points) {
		BPatch_image* appImage = app->getImage();

	std::vector<BPatch_snippet*> printfArgs;
	// Craft the other arguments
	BPatch_constExpr* seven = new BPatch_constExpr(7);

	printfArgs.push_back(seven);

	BPatch_variableExpr* c_log = appImage->findVariable(*(points->front())
							    ,"c_log_process_request",
							    true);

	if (!c_log) {
		fprintf(stderr, "Could not find 'c->log' variable\n");
		return false;
	} else {
		printfArgs.push_back(c_log);
	}

	// Create the printf function call snippet
	BPatch_snippet* fmt =
		new BPatch_constExpr("InterestingProcedure called %d times\n");
	printfArgs.push_back(fmt);
	BPatch_variableExpr* var = appImage->findVariable("myCounter");

	if (!var) {
		fprintf(stderr, "Could not find 'myCounter' variable\n");
		return false;
	} else {
		printfArgs.push_back(var);
	}
	// Find the printf function
	std::vector<BPatch_function*> printfFuncs;
	appImage->findFunction("ngx_log_error_core", printfFuncs);
	//appImage->findFunction("printf", printfFuncs);
	if (printfFuncs.size() == 0) {
		fprintf(stderr, "Could not find printf\n");
		return false;
	}
	// Construct a function call snippet
	BPatch_funcCallExpr printfCall(*(printfFuncs[0]), printfArgs);
	// Insert the snippet
	if (!app->insertSnippet(printfCall, *points)) {
		fprintf(stderr, "insertSnippet failed\n");
		return false;
	}
	return true;
}

bool createAndInsertSnippet3(BPatch_addressSpace* app,
			     std::vector<BPatch_point*>* points) {

	BPatch_image* appImage = app->getImage();
	// (1) Find the open function
	std::vector<BPatch_function *>openFuncs;
	appImage->findFunction("open", openFuncs);
	if (openFuncs.size() == 0) {
		fprintf(stderr, "ERROR: Unable to find function for open()\n");
		return -1;
	}
	// (2) Allocate a vector of snippets for the parameters to open
	std::vector<BPatch_snippet *> openArgs;
	// (3) Create a string constant expression from argv[3]
	BPatch_constExpr fileNameExpr("NGINX_TEST");
	// (4) Create two more constant expressions _WRONLY|O_CREAT and 0666
	BPatch_constExpr fileFlagsExpr(O_WRONLY|O_CREAT);
	BPatch_constExpr fileModeExpr(0666);
	// (5) Push 3 & 4 onto the list from step 2, push first to last
	//parameter.
	openArgs.push_back(&fileNameExpr);
	openArgs.push_back(&fileFlagsExpr);
	openArgs.push_back(&fileModeExpr);
	// (6) create a procedure call using function found at 1 and
	// parameters from step 5.
	BPatch_funcCallExpr openCall(*openFuncs[0], openArgs);

	if (!app->insertSnippet(openCall, *points)) {
		fprintf(stderr, "insertSnippet failed\n");
		return false;
	}


	return true;
}

void finishInstrumenting(BPatch_addressSpace* app, const char* newName)
{
	BPatch_process* appProc = dynamic_cast<BPatch_process*>(app);
	BPatch_binaryEdit* appBin = dynamic_cast<BPatch_binaryEdit*>(app);
	if (appProc) {
		if (!appProc->continueExecution()) {
			fprintf(stderr, "continueExecution failed\n");
		}
		while (!appProc->isTerminated()) {
			bpatch.waitForStatusChange();
		}
	} else if (appBin) {
		if (!appBin->writeFile(newName)) {
			fprintf(stderr, "writeFile failed\n");
		}
	}
}

int main() {
	// Set up information about the program to be instrumented
	const char* progName = "../target/nginx_target/nginx";
	int progPID = 27785;
	const char* progArgv[] = {"../target/nginx_target/nginx", "-h", NULL};
	accessType_t mode = open_file;
	//accessType_t mode = attach;
	// Create/attach/open a binary
	BPatch_addressSpace* app =
	startInstrumenting(mode, progName, progPID, progArgv);
	if (!app) {
		fprintf(stderr, "startInstrumenting failed\n");
		exit(1);
	}
	// Find the entry point for function InterestingProcedure
	const char* interestingFuncName = "ngx_http_process_request";
	std::vector<BPatch_point*>* entryPoint =
	findPoint(app, interestingFuncName, BPatch_entry);
	if (!entryPoint || entryPoint->size() == 0) {
		fprintf(stderr, "No entry points for %s\n", interestingFuncName);
		exit(1);
	}

	// Create and insert instrumentation snippet
	if (!createAndInsertSnippet(app, entryPoint)) {
		fprintf(stderr, "createAndInsertSnippet failed\n");
		exit(1);
	}

	// Find the exit point of main
	std::vector<BPatch_point*>* exitPoint =
		findPoint(app, "ngx_http_process_request", BPatch_exit);
	if (!exitPoint || exitPoint->size() == 0) {
		fprintf(stderr, "No exit points for main\n");
		exit(1);
	}
	//// Create and insert instrumentation snippet 2
	//if (!createAndInsertSnippet2(app, exitPoint)) {
	//	fprintf(stderr, "createAndInsertSnippet2 failed\n");
	//	exit(1);
	//}
	//// Create and insert instrumentation snippet 3
	//if (!createAndInsertSnippet3(app, exitPoint)) {
	//	fprintf(stderr, "createAndInsertSnippet3 failed\n");
	//	exit(1);
	//}

	//Finish instrumentation
	const char* progName2 = "../target/nginx_target/nginx-rewritten";
	finishInstrumenting(app, progName2);
}
