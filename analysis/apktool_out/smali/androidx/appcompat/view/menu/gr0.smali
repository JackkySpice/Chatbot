.class public final Landroidx/appcompat/view/menu/gr0;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final a:Ljava/lang/ClassLoader;


# direct methods
.method public constructor <init>(Ljava/lang/ClassLoader;)V
    .locals 1

    const-string v0, "loader"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/gr0;->a:Ljava/lang/ClassLoader;

    return-void
.end method

.method public static final synthetic a(Landroidx/appcompat/view/menu/gr0;)Ljava/lang/ClassLoader;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/gr0;->a:Ljava/lang/ClassLoader;

    return-object p0
.end method

.method public static final synthetic b(Landroidx/appcompat/view/menu/gr0;)Ljava/lang/Class;
    .locals 0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gr0;->d()Ljava/lang/Class;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final c()Ljava/lang/Class;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/gr0;->a:Ljava/lang/ClassLoader;

    const-string v1, "androidx.window.extensions.WindowExtensions"

    invoke-virtual {v0, v1}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    const-string v1, "loader.loadClass(WindowE\u2026.WINDOW_EXTENSIONS_CLASS)"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final d()Ljava/lang/Class;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/gr0;->a:Ljava/lang/ClassLoader;

    const-string v1, "androidx.window.extensions.WindowExtensionsProvider"

    invoke-virtual {v0, v1}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    const-string v1, "loader.loadClass(WindowE\u2026XTENSIONS_PROVIDER_CLASS)"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final e()Z
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/bo0;->a:Landroidx/appcompat/view/menu/bo0;

    new-instance v1, Landroidx/appcompat/view/menu/gr0$a;

    invoke-direct {v1, p0}, Landroidx/appcompat/view/menu/gr0$a;-><init>(Landroidx/appcompat/view/menu/gr0;)V

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/bo0;->a(Landroidx/appcompat/view/menu/hw;)Z

    move-result v0

    return v0
.end method

.method public final f()Z
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gr0;->e()Z

    move-result v0

    if-eqz v0, :cond_0

    new-instance v0, Landroidx/appcompat/view/menu/gr0$b;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/gr0$b;-><init>(Landroidx/appcompat/view/menu/gr0;)V

    const-string v1, "WindowExtensionsProvider#getWindowExtensions is not valid"

    invoke-static {v1, v0}, Landroidx/appcompat/view/menu/bo0;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/hw;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method
