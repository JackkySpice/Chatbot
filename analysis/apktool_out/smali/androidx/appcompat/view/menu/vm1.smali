.class public final synthetic Landroidx/appcompat/view/menu/vm1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public synthetic a:Landroidx/appcompat/view/menu/hh1;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/hh1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/vm1;->a:Landroidx/appcompat/view/menu/hh1;

    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/vm1;->a:Landroidx/appcompat/view/menu/hh1;

    new-instance v1, Landroidx/appcompat/view/menu/v22;

    iget-object v0, v0, Landroidx/appcompat/view/menu/hh1;->c:Landroidx/appcompat/view/menu/ye1;

    invoke-direct {v1, v0}, Landroidx/appcompat/view/menu/v22;-><init>(Landroidx/appcompat/view/menu/ye1;)V

    return-object v1
.end method
