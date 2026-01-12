.class public Landroidx/lifecycle/r;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/lifecycle/r$a;,
        Landroidx/lifecycle/r$b;,
        Landroidx/lifecycle/r$c;
    }
.end annotation


# instance fields
.field public final a:Landroidx/appcompat/view/menu/w51;

.field public final b:Landroidx/lifecycle/r$b;

.field public final c:Landroidx/appcompat/view/menu/fi;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/w51;Landroidx/lifecycle/r$b;)V
    .locals 7

    .line 1
    const-string v0, "store"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "factory"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v4, 0x0

    const/4 v5, 0x4

    const/4 v6, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    invoke-direct/range {v1 .. v6}, Landroidx/lifecycle/r;-><init>(Landroidx/appcompat/view/menu/w51;Landroidx/lifecycle/r$b;Landroidx/appcompat/view/menu/fi;ILandroidx/appcompat/view/menu/kj;)V

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/w51;Landroidx/lifecycle/r$b;Landroidx/appcompat/view/menu/fi;)V
    .locals 1

    const-string v0, "store"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "factory"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "defaultCreationExtras"

    invoke-static {p3, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/lifecycle/r;->a:Landroidx/appcompat/view/menu/w51;

    iput-object p2, p0, Landroidx/lifecycle/r;->b:Landroidx/lifecycle/r$b;

    iput-object p3, p0, Landroidx/lifecycle/r;->c:Landroidx/appcompat/view/menu/fi;

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/w51;Landroidx/lifecycle/r$b;Landroidx/appcompat/view/menu/fi;ILandroidx/appcompat/view/menu/kj;)V
    .locals 0

    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_0

    .line 3
    sget-object p3, Landroidx/appcompat/view/menu/fi$a;->b:Landroidx/appcompat/view/menu/fi$a;

    .line 4
    :cond_0
    invoke-direct {p0, p1, p2, p3}, Landroidx/lifecycle/r;-><init>(Landroidx/appcompat/view/menu/w51;Landroidx/lifecycle/r$b;Landroidx/appcompat/view/menu/fi;)V

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/x51;Landroidx/lifecycle/r$b;)V
    .locals 1

    const-string v0, "owner"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "factory"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-interface {p1}, Landroidx/appcompat/view/menu/x51;->c()Landroidx/appcompat/view/menu/w51;

    move-result-object v0

    .line 6
    invoke-static {p1}, Landroidx/appcompat/view/menu/v51;->a(Landroidx/appcompat/view/menu/x51;)Landroidx/appcompat/view/menu/fi;

    move-result-object p1

    .line 7
    invoke-direct {p0, v0, p2, p1}, Landroidx/lifecycle/r;-><init>(Landroidx/appcompat/view/menu/w51;Landroidx/lifecycle/r$b;Landroidx/appcompat/view/menu/fi;)V

    return-void
.end method


# virtual methods
.method public a(Ljava/lang/Class;)Landroidx/appcompat/view/menu/u51;
    .locals 3

    const-string v0, "modelClass"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_0

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v0, p1}, Landroidx/lifecycle/r;->b(Ljava/lang/String;Ljava/lang/Class;)Landroidx/appcompat/view/menu/u51;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Local and anonymous classes can not be ViewModels"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public b(Ljava/lang/String;Ljava/lang/Class;)Landroidx/appcompat/view/menu/u51;
    .locals 2

    const-string v0, "key"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "modelClass"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/lifecycle/r;->a:Landroidx/appcompat/view/menu/w51;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/w51;->b(Ljava/lang/String;)Landroidx/appcompat/view/menu/u51;

    move-result-object v0

    invoke-virtual {p2, v0}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const-string p1, "null cannot be cast to non-null type T of androidx.lifecycle.ViewModelProvider.get"

    invoke-static {v0, p1}, Landroidx/appcompat/view/menu/x50;->c(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0

    :cond_0
    new-instance v0, Landroidx/appcompat/view/menu/fe0;

    iget-object v1, p0, Landroidx/lifecycle/r;->c:Landroidx/appcompat/view/menu/fi;

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/fe0;-><init>(Landroidx/appcompat/view/menu/fi;)V

    sget-object v1, Landroidx/lifecycle/r$c;->c:Landroidx/appcompat/view/menu/fi$b;

    invoke-virtual {v0, v1, p1}, Landroidx/appcompat/view/menu/fe0;->b(Landroidx/appcompat/view/menu/fi$b;Ljava/lang/Object;)V

    :try_start_0
    iget-object v1, p0, Landroidx/lifecycle/r;->b:Landroidx/lifecycle/r$b;

    invoke-interface {v1, p2, v0}, Landroidx/lifecycle/r$b;->b(Ljava/lang/Class;Landroidx/appcompat/view/menu/fi;)Landroidx/appcompat/view/menu/u51;

    move-result-object p2
    :try_end_0
    .catch Ljava/lang/AbstractMethodError; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    iget-object v0, p0, Landroidx/lifecycle/r;->b:Landroidx/lifecycle/r$b;

    invoke-interface {v0, p2}, Landroidx/lifecycle/r$b;->a(Ljava/lang/Class;)Landroidx/appcompat/view/menu/u51;

    move-result-object p2

    :goto_0
    iget-object v0, p0, Landroidx/lifecycle/r;->a:Landroidx/appcompat/view/menu/w51;

    invoke-virtual {v0, p1, p2}, Landroidx/appcompat/view/menu/w51;->c(Ljava/lang/String;Landroidx/appcompat/view/menu/u51;)V

    return-object p2
.end method
