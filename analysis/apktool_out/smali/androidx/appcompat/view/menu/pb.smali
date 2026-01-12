.class public final synthetic Landroidx/appcompat/view/menu/pb;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/ub;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/ub;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/pb;->m:Landroidx/appcompat/view/menu/ub;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/pb;->m:Landroidx/appcompat/view/menu/ub;

    invoke-static {v0}, Landroidx/appcompat/view/menu/ub;->z(Landroidx/appcompat/view/menu/ub;)V

    return-void
.end method
