.class public final Landroidx/appcompat/view/menu/gr0$a;
.super Landroidx/appcompat/view/menu/d80;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/hw;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/gr0;->e()Z
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field public final synthetic n:Landroidx/appcompat/view/menu/gr0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/gr0;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/gr0$a;->n:Landroidx/appcompat/view/menu/gr0;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Class;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/gr0$a;->n:Landroidx/appcompat/view/menu/gr0;

    invoke-static {v0}, Landroidx/appcompat/view/menu/gr0;->a(Landroidx/appcompat/view/menu/gr0;)Ljava/lang/ClassLoader;

    move-result-object v0

    const-string v1, "androidx.window.extensions.WindowExtensionsProvider"

    invoke-virtual {v0, v1}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    const-string v1, "loader.loadClass(WindowE\u2026XTENSIONS_PROVIDER_CLASS)"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public bridge synthetic d()Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gr0$a;->a()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method
