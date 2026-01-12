.class public final Landroidx/appcompat/view/menu/xq;
.super Landroidx/appcompat/view/menu/o;
.source "SourceFile"


# instance fields
.field public final o:Landroidx/appcompat/view/menu/xq$a;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Landroidx/appcompat/view/menu/o;-><init>()V

    new-instance v0, Landroidx/appcompat/view/menu/xq$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/xq$a;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/xq;->o:Landroidx/appcompat/view/menu/xq$a;

    return-void
.end method


# virtual methods
.method public c()Ljava/util/Random;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/xq;->o:Landroidx/appcompat/view/menu/xq$a;

    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "implStorage.get()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/util/Random;

    return-object v0
.end method
